package turnconn

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/client/internal/appcfg"
	"github.com/cacggghp/vk-turn-proxy/client/internal/appstate"
	"github.com/cacggghp/vk-turn-proxy/client/internal/dispatcher"
	"github.com/cacggghp/vk-turn-proxy/client/internal/netadapt"
	"github.com/cacggghp/vk-turn-proxy/client/internal/vkauth"
	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}

	select {
	case appstate.HandshakeSem <- struct{}{}:
		defer func() { <-appstate.HandshakeSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	ctx1, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dtlsConn, err := dtls.ClientWithOptions(
		conn,
		peer,
		dtls.WithCertificates(certificate),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()),
	)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *dispatcher.UDPPacket, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) error {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)

	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		return fmt.Errorf("failed to connect DTLS: %s", err1)
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			log.Printf("[STREAM %d] failed to close DTLS connection: %s", streamID, closeErr)
		}
		log.Printf("[STREAM %d] Closed DTLS connection\n", streamID)
	}()
	log.Printf("[STREAM %d] Established DTLS connection!\n", streamID)

	if okchan != nil {
		go func() {
			select {
			case okchan <- struct{}{}:
			case <-dtlsctx.Done():
			}
		}()
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	context.AfterFunc(dtlsctx, func() {
		if err := dtlsConn.SetDeadline(time.Now()); err != nil {
			log.Printf("[STREAM %d] Warning: SetDeadline failed: %v", streamID, err)
		}
	})

	go func() {
		defer dtlscancel()
		for {
			select {
			case <-dtlsctx.Done():
				return
			case pkt := <-inboundChan:
				_, _ = dtlsConn.Write(pkt.Data[:pkt.N])
				dispatcher.PacketPool.Put(pkt)
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				return
			}

			// Send back to the active WG client
			if peerAddr := appstate.ActiveLocalPeer.Load(); peerAddr != nil {
				if addr, ok := peerAddr.(net.Addr); ok {
					if _, err := listenConn.WriteTo(buf[:n], addr); err != nil {
						log.Printf("[STREAM %d] failed to forward packet to local peer: %v", streamID, err)
					}
				}
			}
		}
	}()

	wg.Wait()
	if err := dtlsConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("[STREAM %d] Failed to clear DTLS deadline: %s", streamID, err)
	}
	return nil
}

// GetCredsFunc fetches TURN credentials for the given stream and returns
// (username, password, serverAddr, error).
type GetCredsFunc func(ctx context.Context, link string, streamID int) (string, string, string, error)

type Params struct {
	Host     string
	Port     string
	Links    []string
	UDP      bool
	GetCreds GetCredsFunc
	Cfg      *appcfg.Config
}

// PickLink chooses a link for given streamID via round-robin shard.
// Empty Links → empty string (caller treats as misconfig).
func (p *Params) PickLink(streamID int) string {
	if len(p.Links) == 0 {
		return ""
	}
	idx := streamID % len(p.Links)
	if idx < 0 {
		idx += len(p.Links)
	}
	return p.Links[idx]
}

// turnAllocation bundles a single TURN session: the dial socket, the TURN client,
// and the relayed PacketConn returned by Allocate.
type turnAllocation struct {
	dialConn io.Closer
	client   *turn.Client
	relay    net.PacketConn
}

func (a *turnAllocation) close() {
	if a.relay != nil {
		_ = a.relay.Close()
	}
	if a.client != nil {
		a.client.Close()
	}
	if a.dialConn != nil {
		_ = a.dialConn.Close()
	}
}

// dialTurn opens a fresh TURN session under the given (user, pass). Each call
// produces an independent 5-tuple (own source UDP/TCP port) and an independent
// TURN allocation. VK may or may not allow multiple allocations under the same
// credentials — caller is expected to tolerate failures on additional sessions.
func dialTurn(ctx context.Context, params *Params, turnServerAddr string, turnServerUDPAddr *net.UDPAddr, addrFamily turn.RequestedAddressFamily, user, pass string) (*turnAllocation, error) {
	var dialCloser io.Closer
	var turnConn net.PacketConn
	if params.UDP {
		conn, err := net.DialUDP("udp", nil, turnServerUDPAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to TURN server: %w", err)
		}
		dialCloser = conn
		turnConn = &netadapt.ConnectedUDPConn{UDPConn: conn}
	} else {
		ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var d net.Dialer
		conn, err := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to TURN server: %w", err)
		}
		dialCloser = conn
		turnConn = turn.NewSTUNConn(&netadapt.CountingConn{Conn: conn})
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Net:                    netadapt.NewDirectNet(),
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		_ = dialCloser.Close()
		return nil, fmt.Errorf("failed to create TURN client: %w", err)
	}

	if err = client.Listen(); err != nil {
		client.Close()
		_ = dialCloser.Close()
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = dialCloser.Close()
		return nil, fmt.Errorf("failed to allocate: %w", err)
	}

	return &turnAllocation{dialConn: dialCloser, client: client, relay: relay}, nil
}

// relayPool is a concurrent ring of live relay PacketConns. Reads (pick) are
// non-blocking and lock-free on the hot path; mutation (add/remove) is rare.
type relayPool struct {
	mu      sync.RWMutex
	relays  []net.PacketConn
	counter atomic.Uint64
}

func (p *relayPool) add(r net.PacketConn) {
	p.mu.Lock()
	p.relays = append(p.relays, r)
	p.mu.Unlock()
}

func (p *relayPool) pick() net.PacketConn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.relays)
	if n == 0 {
		return nil
	}
	idx := int(p.counter.Add(1)-1) % n
	return p.relays[idx]
}

func oneTurnConnection(ctx context.Context, params *Params, peer *net.UDPAddr, conn2 net.PacketConn, streamID int, c chan<- error) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error
	defer func() { c <- err }()
	user, pass, urlTarget, err1 := params.GetCreds(ctx, params.PickLink(streamID), streamID)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	urlhost, urlport, err1 := net.SplitHostPort(urlTarget)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		return
	}
	if params.Host != "" {
		urlhost = params.Host
	}
	if params.Port != "" {
		urlport = params.Port
	}
	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	log.Printf("[STREAM %d] [TURN] dialing %s (udp=%v)", streamID, turnServerAddr, params.UDP)
	turnServerUDPAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUDPAddr.String()
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	primary, err1 := dialTurn(ctx, params, turnServerAddr, turnServerUDPAddr, addrFamily, user, pass)
	if err1 != nil {
		if vkauth.IsAuthError(err1) {
			vkauth.HandleAuthError(streamID)
		}
		err = err1
		return
	}

	vkauth.ResetErrorCount(streamID)

	appstate.ConnectedStreams.Add(1)
	defer appstate.ConnectedStreams.Add(-1)

	if params.Cfg.Debug {
		log.Printf("[STREAM %d] relayed-address=%s", streamID, primary.relay.LocalAddr().String())
	}

	pool := &relayPool{}
	pool.add(primary.relay)

	turnctx, turncancel := context.WithCancel(ctx)
	defer turncancel()

	// Track all allocations for clean shutdown.
	allocs := []*turnAllocation{primary}
	var allocsMu sync.Mutex
	defer func() {
		allocsMu.Lock()
		for _, a := range allocs {
			if a.relay != nil {
				_ = a.relay.SetDeadline(time.Now()) //nolint:errcheck
			}
		}
		toClose := allocs
		allocs = nil
		allocsMu.Unlock()
		for _, a := range toClose {
			a.close()
		}
	}()

	context.AfterFunc(turnctx, func() {
		allocsMu.Lock()
		defer allocsMu.Unlock()
		for _, a := range allocs {
			if a.relay != nil {
				_ = a.relay.SetDeadline(time.Now()) //nolint:errcheck
			}
		}
	})

	// Inbound goroutine factory: per-relay reader feeding decrypted-side conn2.
	var inboundWg sync.WaitGroup
	dummyAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	spawnInbound := func(relay net.PacketConn) {
		inboundWg.Add(1)
		go func() {
			defer inboundWg.Done()
			defer turncancel()
			buf := make([]byte, 1600)
			for {
				n, _, err1 := relay.ReadFrom(buf)
				if err1 != nil {
					return
				}
				// Write to the AsyncPacketPipe (which ignores the dummy address).
				// We don't need to wait for outbound packets to establish an address,
				// which was causing incoming proxy server responses to be dropped
				// on multi-link setups where some streams only receive packets.
				if _, err := conn2.WriteTo(buf[:n], dummyAddr); err != nil {
					return
				}
			}
		}()
	}
	spawnInbound(primary.relay)

	// Outbound: read from conn2, send via round-robin across the relay pool.
	go func() {
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			if turnctx.Err() != nil {
				return
			}
			n, _, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				return
			}
			if turnctx.Err() != nil {
				return
			}

			r := pool.pick()
			if r == nil {
				return
			}
			if _, err1 = r.WriteTo(buf[:n], peer); err1 != nil {
				return
			}
		}
	}()

	// Open extra allocations under the same creds. DTLS handshake completes
	// over the primary first; deferring extras lets the server install the
	// Connection ID so subsequent multi-path packets are matched to the
	// existing session via CID rather than 5-tuple.
	extras := params.Cfg.AllocsPerStream - 1
	if extras > 0 {
		go func() {
			select {
			case <-turnctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			for i := 0; i < extras; i++ {
				if turnctx.Err() != nil {
					return
				}
				extra, err := dialTurn(ctx, params, turnServerAddr, turnServerUDPAddr, addrFamily, user, pass)
				if err != nil {
					log.Printf("[STREAM %d] [TURN] extra alloc %d/%d failed: %v", streamID, i+1, extras, err)
					continue
				}
				log.Printf("[STREAM %d] [TURN] extra alloc %d/%d OK relay=%s", streamID, i+1, extras, extra.relay.LocalAddr())
				allocsMu.Lock()
				allocs = append(allocs, extra)
				allocsMu.Unlock()
				pool.add(extra.relay)
				spawnInbound(extra.relay)
				time.Sleep(200 * time.Millisecond) // jitter the bring-up
			}
		}()
	}

	inboundWg.Wait()
}

func DtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *dispatcher.UDPPacket, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := oneDtlsConnection(ctx, peer, listenConn, inboundChan, connchan, okchan, streamID)
			if err == nil {
				continue
			}
			// During captcha lockout the upstream auth path stalls and DTLS
			// handshakes time out. Wait for the lockout to clear instead of
			// spinning on `continue`.
			if lockout := appstate.GlobalCaptchaLockout.Load(); time.Now().Unix() < lockout && strings.Contains(err.Error(), "context deadline exceeded") {
				wait := time.Until(time.Unix(lockout, 0))
				if wait < time.Second {
					wait = time.Second
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(10+rand.Intn(20)) * time.Second):
			}
		}
	}
}

func TurnConnectionLoop(ctx context.Context, params *Params, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
			case <-ctx.Done():
				return
			}
			c := make(chan error)
			go oneTurnConnection(ctx, params, peer, conn2, streamID, c)

			if err := <-c; err != nil {
				if strings.Contains(err.Error(), "FATAL_CAPTCHA") {
					log.Printf("[STREAM %d] Fatal manual captcha error. Shutting down application.", streamID)
					if params.Cfg.AppCancel != nil {
						params.Cfg.AppCancel()
					}
					return
				}
				if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") {
					if !strings.Contains(err.Error(), "global lockout active") {
						log.Printf("[STREAM %d] Backing off for 60 seconds to avoid IP ban...", streamID)
						select {
						case <-ctx.Done():
							return
						case <-time.After(60 * time.Second):
						}
					} else {
						lockoutEnd := appstate.GlobalCaptchaLockout.Load()
						sleepDuration := time.Until(time.Unix(lockoutEnd, 0))
						if sleepDuration < 0 {
							sleepDuration = 5 * time.Second
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(sleepDuration):
						}
					}
				} else {
					log.Printf("[STREAM %d] %s", streamID, err)
					time.Sleep(2 * time.Second)
				}
			}
		}
	}
}
