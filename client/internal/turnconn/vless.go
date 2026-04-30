package turnconn

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/client/internal/ishlisten"
	"github.com/cacggghp/vk-turn-proxy/client/internal/netadapt"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/xtaci/smux"
)

// sessionPool manages a pool of smux sessions for round-robin TCP distribution.
type sessionPool struct {
	mu       sync.RWMutex
	sessions []*smux.Session
	counter  atomic.Uint64
}

func (p *sessionPool) add(s *smux.Session) {
	p.mu.Lock()
	p.sessions = append(p.sessions, s)
	p.mu.Unlock()
}

func (p *sessionPool) remove(s *smux.Session) {
	p.mu.Lock()
	for i, sess := range p.sessions {
		if sess == s {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
}

func (p *sessionPool) pick() *smux.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.sessions)
	if n == 0 {
		return nil
	}
	idx := p.counter.Add(1) % uint64(n)
	return p.sessions[idx]
}

func (p *sessionPool) count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

// RunVLESSMode implements TCP forwarding with round-robin across N TURN sessions.
func RunVLESSMode(ctx context.Context, tp *Params, peer *net.UDPAddr, listenAddr string, numSessions int) {
	pool := &sessionPool{}

	// Bind the TCP listener up-front so the host UI sees the port bound
	// immediately. Sessions can take many seconds to establish (captcha +
	// throttled identity acquisition); deferring the bind until the first
	// session is up causes UIs that watch for the socket to time out and
	// kill the process. Connections that arrive before any session is
	// active are rejected by the pool.pick() == nil branch below.
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panicf("TCP listen: %s", err)
	}

	wrappedListener, err := ishlisten.Wrap(listener)
	if err != nil {
		log.Printf("Warning: failed to wrap listener: %v", err)
		wrappedListener = listener
	}

	context.AfterFunc(ctx, func() { _ = wrappedListener.Close() })
	log.Printf("VLESS mode: listening on %s (round-robin across %d sessions, sessions connecting...)", listenAddr, numSessions)
	// Legacy line preserved verbatim — the Android host parses it via
	// VLESS_TOTAL_REGEX to populate the connection-stats target.
	log.Printf("VLESS mode: waiting for sessions to connect (total: %d)...", numSessions)

	// Coordinated cold start: maintainer 0 runs immediately so the first
	// VK identity (and its captcha) is acquired exactly once. Maintainers
	// 1..N-1 wait until pool has at least one active session, then stagger
	// 200ms apart. By then identity caches are warm, so they only execute
	// the lightweight slot-acquisition path (gated by per-identity slotMu).
	// This preserves the original streamID%n credential sharding without
	// forcing N captchas serialised under vkRequestMu on cold start.
	var wgMaint sync.WaitGroup
	wgMaint.Add(1)
	go func() {
		defer wgMaint.Done()
		maintainVLESSSession(ctx, tp, peer, 0, pool)
	}()

	for i := 1; i < numSessions; i++ {
		wgMaint.Add(1)
		go func(id int) {
			defer wgMaint.Done()
			// Wait for pool to have an active session before joining,
			// so identity caches are warm and we don't pile up under
			// vkRequestMu.
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(150 * time.Millisecond):
				}
				if pool.count() > 0 {
					break
				}
			}
			// Light stagger so 11 maintainers don't fire slot acquires
			// in the same instant.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(id-1) * 200 * time.Millisecond):
			}
			maintainVLESSSession(ctx, tp, peer, id, pool)
		}(i)
	}

	var wgConn sync.WaitGroup
	for {
		tcpConn, err := wrappedListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wgConn.Wait()
				wgMaint.Wait()
				return
			default:
			}
			log.Printf("TCP accept error: %s", err)
			continue
		}

		sess := pool.pick()
		if sess == nil || sess.IsClosed() {
			log.Printf("No active sessions, rejecting connection")
			_ = tcpConn.Close()
			continue
		}

		wgConn.Add(1)
		go func(tc net.Conn, s *smux.Session) {
			defer wgConn.Done()
			defer func() { _ = tc.Close() }()
			stream, err := s.OpenStream()
			if err != nil {
				log.Printf("smux open stream error: %s", err)
				return
			}
			defer func() { _ = stream.Close() }()
			pipe(ctx, tc, stream, tp.Cfg.Debug)
		}(tcpConn, sess)
	}
}

// maintainVLESSSession keeps one TURN+DTLS+KCP+smux session alive, reconnecting on failure.
func maintainVLESSSession(ctx context.Context, tp *Params, peer *net.UDPAddr, id int, pool *sessionPool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		smuxSess, cleanup, err := createSmuxSession(ctx, tp, peer, id)
		if err != nil {
			log.Printf("[session %d] setup error: %s, retrying...", id, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}

		pool.add(smuxSess)
		log.Printf("[session %d] connected (active: %d)", id, pool.count())

		for !smuxSess.IsClosed() {
			select {
			case <-ctx.Done():
				pool.remove(smuxSess)
				cleanup()
				return
			case <-time.After(1 * time.Second):
			}
		}

		pool.remove(smuxSess)
		cleanup()
		log.Printf("[session %d] disconnected (active: %d), reconnecting...", id, pool.count())

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// createSmuxSession establishes a full TURN+DTLS+KCP+smux pipeline and returns
// the smux session along with a cleanup function to tear down all layers.
func createSmuxSession(ctx context.Context, tp *Params, peer *net.UDPAddr, id int) (*smux.Session, func(), error) {
	var cleanupFns []func()
	cleanup := func() {
		for i := len(cleanupFns) - 1; i >= 0; i-- {
			cleanupFns[i]()
		}
	}

	// 1. Get TURN credentials
	user, pass, rawURL, err := tp.GetCreds(ctx, tp.Link, id)
	if err != nil {
		return nil, nil, fmt.Errorf("get TURN creds: %w", err)
	}
	urlhost, urlport, err := net.SplitHostPort(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse TURN addr: %w", err)
	}
	if tp.Host != "" {
		urlhost = tp.Host
	}
	if tp.Port != "" {
		urlport = tp.Port
	}
	turnServerAddr := net.JoinHostPort(urlhost, urlport)
	turnServerUDPAddr, err := net.ResolveUDPAddr("udp", turnServerAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve TURN addr: %w", err)
	}
	turnServerAddr = turnServerUDPAddr.String()

	// 2. Connect to TURN server
	var turnConn net.PacketConn
	ctx1, cancel1 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel1()
	if tp.UDP {
		c, err1 := net.DialUDP("udp", nil, turnServerUDPAddr)
		if err1 != nil {
			return nil, nil, fmt.Errorf("dial TURN (udp): %w", err1)
		}
		cleanupFns = append(cleanupFns, func() { _ = c.Close() })
		turnConn = &netadapt.ConnectedUDPConn{UDPConn: c}
	} else {
		var d net.Dialer
		c, err1 := d.DialContext(ctx1, "tcp", turnServerAddr)
		if err1 != nil {
			return nil, nil, fmt.Errorf("dial TURN (tcp): %w", err1)
		}
		cleanupFns = append(cleanupFns, func() { _ = c.Close() })
		turnConn = turn.NewSTUNConn(c)
	}

	// 3. Create TURN client and allocate relay
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
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
	turnClient, err := turn.NewClient(cfg)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create TURN client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { turnClient.Close() })
	if err = turnClient.Listen(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN listen: %w", err)
	}
	relayConn, err := turnClient.Allocate()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = relayConn.Close() })
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	// 4. Establish DTLS over TURN relay
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("generate cert: %w", err)
	}
	dtlsPC := &netadapt.RelayPacketConn{Relay: relayConn, Peer: peer}
	dtlsConn, err := dtls.ClientWithOptions(dtlsPC, peer,
		dtls.WithCertificates(certificate),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()),
	)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("DTLS client create: %w", err)
	}
	ctx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()
	if err = dtlsConn.HandshakeContext(ctx2); err != nil {
		_ = dtlsConn.Close()
		cleanup()
		return nil, nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = dtlsConn.Close() })
	log.Printf("DTLS connection established")

	// 5. Create KCP session over DTLS
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, false)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("KCP session: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = kcpSess.Close() })
	log.Printf("KCP session established")

	// 6. Create smux client session over KCP
	smuxSess, err := smux.Client(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("smux client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = smuxSess.Close() })
	log.Printf("smux session established")

	return smuxSess, cleanup, nil
}

// pipe copies data bidirectionally between two connections.
func pipe(ctx context.Context, c1, c2 net.Conn, debug bool) {
	ctx2, cancel := context.WithCancel(ctx)
	context.AfterFunc(ctx2, func() {
		if err := c1.SetDeadline(time.Now()); err != nil {
			log.Printf("pipe: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			log.Printf("pipe: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		if _, err := io.Copy(c1, c2); err != nil {
			if debug {
				log.Printf("pipe: c1<-c2 copy error: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		if _, err := io.Copy(c2, c1); err != nil {
			if debug {
				log.Printf("pipe: c2<-c1 copy error: %v", err)
			}
		}
	}()
	wg.Wait()
	if err := c1.SetDeadline(time.Time{}); err != nil {
		if debug {
			log.Printf("pipe: failed to reset deadline c1: %v", err)
		}
	}
	if err := c2.SetDeadline(time.Time{}); err != nil {
		if debug {
			log.Printf("pipe: failed to reset deadline c2: %v", err)
		}
	}
}
