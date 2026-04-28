// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/client/internal/appcfg"
	"github.com/cacggghp/vk-turn-proxy/client/internal/appstate"
	"github.com/cacggghp/vk-turn-proxy/client/internal/dispatcher"
	"github.com/cacggghp/vk-turn-proxy/client/internal/dnsdial"
	"github.com/cacggghp/vk-turn-proxy/client/internal/turnconn"
	"github.com/cacggghp/vk-turn-proxy/client/internal/vkauth"
	"github.com/cacggghp/vk-turn-proxy/client/internal/yandexauth"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		log.Fatalf("Exit...\n")
	}()

	if len(os.Args) > 1 && strings.Contains(os.Args[0], "linker") {
		os.Args = os.Args[1:]
	}

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vklink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yalink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	peerAddr := flag.String("peer", "", "peer server address (host:port)")
	n := flag.Int("n", 0, "connections to TURN (default 10 for VK, 1 for Yandex)")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	vlessMode := flag.Bool("vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	debugFlag := flag.Bool("debug", false, "enable debug logging")
	manualCaptchaFlag := flag.Bool("manual-captcha", false, "skip auto captcha solving, use manual mode immediately")
	dnsFlag := flag.String("dns", dnsdial.DNSModeAuto, "DNS resolution mode: udp | doh | auto (auto tries UDP/53 first, sticky-fallback to DoH on total failure)")
	allocsFlag := flag.Int("allocs-per-stream", 1, "open this many TURN allocations per stream under shared creds (variant A — only useful if VK throttles per-allocation)")
	flag.Parse()
	switch *dnsFlag {
	case dnsdial.DNSModeUDP, dnsdial.DNSModeDoH, dnsdial.DNSModeAuto:
	default:
		log.Panicf("invalid -dns value %q (expected udp|doh|auto)", *dnsFlag)
	}

	cfg := &appcfg.Config{
		Debug:                *debugFlag,
		ManualCaptcha:        *manualCaptchaFlag,
		AutoCaptchaSliderPOC: !*manualCaptchaFlag,
		DNSMode:              *dnsFlag,
		UDP:                  *udp,
		AllocsPerStream:      *allocsFlag,
		AppCancel:            cancel,
	}

	log.Printf("[DNS] mode=%s", cfg.DNSMode)
	dnsdial.InstallGlobalResolver(cfg.DNSMode)
	if *peerAddr == "" {
		log.Panicf("Need peer address!")
	}
	peer, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		panic(err)
	}
	if (*vklink == "") == (*yalink == "") {
		log.Panicf("Need either vk-link or yandex-link!")
	}

	var link string
	var getCreds turnconn.GetCredsFunc
	if *vklink != "" {
		parts := strings.Split(*vklink, "join/")
		link = parts[len(parts)-1]

		getCreds = func(ctx context.Context, s string, streamID int) (string, string, string, error) {
			return vkauth.GetCredsCached(ctx, s, streamID, cfg)
		}
		if *n <= 0 {
			*n = 10
		}
	} else {
		parts := strings.Split(*yalink, "j/")
		link = parts[len(parts)-1]
		getCreds = func(ctx context.Context, s string, streamID int) (string, string, string, error) {
			return yandexauth.GetCreds(s, cfg)
		}
		if *n <= 0 {
			*n = 1
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	params := &turnconn.Params{
		Host:     *host,
		Port:     *port,
		Link:     link,
		UDP:      *udp,
		GetCreds: getCreds,
		Cfg:      cfg,
	}

	if *vlessMode {
		turnconn.RunVLESSMode(ctx, params, peer, *listen, *n)
		return
	}

	listenConn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Printf("Failed to close local connection: %s", closeErr)
		}
	})

	numStreams := *n
	if numStreams <= 0 {
		numStreams = 1
	}

	// Shared Worker Pool Queue for Aggregation
	inboundChan := make(chan *dispatcher.UDPPacket, 2000)

	go func() {
		for {
			pktIface := dispatcher.PacketPool.Get()
			pkt, ok := pktIface.(*dispatcher.UDPPacket)
			if !ok {
				log.Printf("packetPool returned unexpected type: %T", pktIface)
				continue
			}
			nRead, addr, err := listenConn.ReadFrom(pkt.Data)
			if err != nil {
				return
			}

			// Save the local WireGuard peer address
			current := appstate.ActiveLocalPeer.Load()
			if current == nil {
				appstate.ActiveLocalPeer.Store(addr)
			} else if addrStr, ok := current.(net.Addr); ok {
				if addrStr.String() != addr.String() {
					appstate.ActiveLocalPeer.Store(addr)
				}
			} else {
				appstate.ActiveLocalPeer.Store(addr)
			}

			pkt.N = nRead

			select {
			case inboundChan <- pkt:
			default:
				// Drop the packet only if the global queue is completely full
				dispatcher.PacketPool.Put(pkt)
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)

	okchan := make(chan struct{})
	connchan := make(chan net.PacketConn)
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		turnconn.DtlsConnectionLoop(ctx, peer, listenConn, inboundChan, connchan, okchan, 1)
	}()
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		turnconn.TurnConnectionLoop(ctx, params, peer, connchan, t, 1)
	}()

	select {
	case <-okchan:
	case <-ctx.Done():
	}

	for i := 2; i <= numStreams; i++ {
		cchan := make(chan net.PacketConn)
		wg1.Add(1)
		go func(streamID int) {
			defer wg1.Done()
			turnconn.DtlsConnectionLoop(ctx, peer, listenConn, inboundChan, cchan, nil, streamID)
		}(i)
		wg1.Add(1)
		go func(streamID int) {
			defer wg1.Done()
			turnconn.TurnConnectionLoop(ctx, params, peer, cchan, t, streamID)
		}(i)
	}

	wg1.Wait()
}
