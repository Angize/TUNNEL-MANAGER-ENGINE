package dnstun

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

// pipeTransport is an in-memory WireTransport: Send delivers onto the peer's rx channel (dropping
// a lossPct fraction to model an unreliable DNS channel), Recv reads this end's rx. A cross-wired
// pair stands in for the real DNS transport so the session layer is testable without a resolver.
type pipeTransport struct {
	tx     chan []byte // datagrams this end sends (the peer's rx)
	rx     chan []byte // datagrams this end receives
	loss   int
	mu     sync.Mutex // guards rng (math/rand/v2 is not concurrency-safe)
	rng    *mrand.Rand
	closed chan struct{}
	once   sync.Once
}

func newPipePair(lossPct int) (client, server *pipeTransport) {
	c2s := make(chan []byte, 1024)
	s2c := make(chan []byte, 1024)
	client = &pipeTransport{tx: c2s, rx: s2c, loss: lossPct, rng: mrand.New(mrand.NewPCG(1, 2)), closed: make(chan struct{})}
	server = &pipeTransport{tx: s2c, rx: c2s, loss: lossPct, rng: mrand.New(mrand.NewPCG(3, 4)), closed: make(chan struct{})}
	return
}

func (p *pipeTransport) Send(d []byte) error {
	select {
	case <-p.closed:
		return net.ErrClosed
	default:
	}
	p.mu.Lock()
	drop := p.loss > 0 && p.rng.IntN(100) < p.loss
	p.mu.Unlock()
	if drop {
		return nil // lost in transit — kcp-go retransmits
	}
	cp := append([]byte(nil), d...)
	select {
	case p.tx <- cp:
	case <-p.closed:
	default: // peer not draining: drop
	}
	return nil
}

func (p *pipeTransport) Recv() ([]byte, error) {
	select {
	case d := <-p.rx:
		return d, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *pipeTransport) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// TestSessionOverLossyPipe is the Phase-A end-to-end proof: two sessions (dial + serve) complete
// the X25519 handshake and exchange an AEAD-sealed, reliable byte stream IN BOTH DIRECTIONS over
// a 15%-lossy transport — the whole session layer the DNS carrier rides on, minus the DNS codec.
func TestSessionOverLossyPipe(t *testing.T) {
	cliT, srvT := newPipePair(15)
	cfg := SessionConfig{PSK: "correct-horse-battery-staple", Cipher: "chacha20"}

	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err != nil {
			t.Errorf("ServeSession: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- c
	}()

	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer cli.Close()

	const payloadSize = 24 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// Client writes upstream; a reader collects the echo. The write must start so the server's
	// AcceptKCP (blocked on the first KCP datagram) returns.
	go func() { _, _ = cli.Write(payload) }()

	srv := <-srvCh
	if srv == nil {
		t.Fatal("server session failed")
	}
	defer srv.Close()

	// Server echoes full-duplex (separate concern from its own reads — one read loop that writes
	// each chunk back; never io.Copy on the same session, which self-stalls half-duplex).
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := srv.Read(buf)
			if err != nil {
				return
			}
			if _, err := srv.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	got := make([]byte, payloadSize)
	readDone := make(chan error, 1)
	go func() {
		off := 0
		buf := make([]byte, 4096)
		for off < len(got) {
			n, err := cli.Read(buf)
			if err != nil {
				readDone <- err
				return
			}
			copy(got[off:], buf[:n])
			off += n
		}
		readDone <- nil
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out: session did not converge under loss")
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch: sealed reliable stream corrupted data")
	}
}

// TestSessionWrongPSKFails proves the handshake authenticates: a client with the wrong PSK cannot
// establish a session — the server never MAC-verifies its init, so it never answers and the dial
// times out (rather than silently forming an unauthenticated tunnel).
func TestSessionWrongPSKFails(t *testing.T) {
	orig := handshakeTimeout
	handshakeTimeout = 1200 * time.Millisecond
	defer func() { handshakeTimeout = orig }()

	cliT, srvT := newPipePair(0)
	go func() { _, _ = ServeSession(srvT, SessionConfig{PSK: "server-psk", Cipher: "chacha20"}) }()

	_, err := DialSession(cliT, SessionConfig{PSK: "wrong-client-psk", Cipher: "chacha20"})
	if err == nil {
		t.Fatal("DialSession succeeded with a mismatched PSK — handshake did not authenticate")
	}
}

// TestServeSessionRecoversFromVanishedClient proves the server's single session slot recovers
// PROMPTLY from a client that arms it (a valid init) then vanishes before completing the KCP
// handshake (crash, or its own resp was lost so it timed out). A NEW client that fully dials and
// writes must be ADOPTED IN PLACE and served — the server reads its data — with no reconnect and no
// re-init, in about one round trip rather than a KCP dead-link timeout.
func TestServeSessionRecoversFromVanishedClient(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "recover-me", Cipher: "chacha20"}

	srvCh := make(chan net.Conn, 1)
	srvErr := make(chan error, 1)
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err != nil {
			srvErr <- err
			return
		}
		srvCh <- c
	}()

	// Client 1 arms the server with a valid init, then goes silent (never completes KCP).
	ci1, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci1)...))
	time.Sleep(200 * time.Millisecond) // let the server arm and enter AcceptKCP

	select {
	case err := <-srvErr:
		t.Fatalf("ServeSession returned before a new client dialed: %v", err)
	case <-srvCh:
		t.Fatal("ServeSession returned before a new client dialed")
	default:
	}

	// Client 2 fully dials with a fresh ephemeral over the SAME transport and writes — a real new
	// client completing the KCP handshake. The server must adopt it in place and serve it.
	cli2, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("client 2 DialSession: %v", err)
	}
	defer cli2.Close()
	payload := []byte("hello from the second client")
	go func() { _, _ = cli2.Write(payload) }()

	select {
	case err := <-srvErr:
		t.Fatalf("ServeSession errored instead of adopting the new client: %v", err)
	case srv := <-srvCh:
		defer srv.Close()
		got := make([]byte, len(payload))
		_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(srv, got); err != nil {
			t.Fatalf("server read from the adopted client: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("adopted-client data mismatch: got %q want %q", got, payload)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeSession stayed parked after a new client fully dialed (no adopt)")
	}
}

// TestServeSessionIgnoresReplayedInit locks in the replayed-init DoS protection: once a client has
// ESTABLISHED and data is flowing, a bare different-ephemeral init with NO follow-up data — exactly
// what an on-path attacker replaying a captured init can produce — must NOT tear the live session
// down. Only a data frame that actually opens under the staged keys (which a replay cannot forge)
// may promote.
func TestServeSessionIgnoresReplayedInit(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "no-teardown", Cipher: "chacha20"}

	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err != nil {
			t.Errorf("ServeSession: %v", err)
			srvCh <- nil
			return
		}
		srvCh <- c
	}()

	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer cli.Close()
	// Keep a steady trickle of data so the session establishes and stays demonstrably live.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := cli.Write([]byte("ping")); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	srv := <-srvCh
	if srv == nil {
		t.Fatal("server session failed to establish")
	}
	defer srv.Close()
	buf := make([]byte, 64)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("server first read (establish): %v", err)
	}

	// Inject a bare, DIFFERENT-ephemeral init (a replay) with no follow-up data frame.
	attacker, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, attacker)...))

	// The live session must keep working: the server keeps reading the real client's data.
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("live session was disrupted by a bare replayed init: %v", err)
	}
}

// TestServeSessionUnblocksOnTransportClose proves Close honors its contract even before a client
// connects: with the server armed and parked in AcceptKCP, closing the transport (what the
// carrier's Close does when no session is live yet) must unblock ServeSession — otherwise the
// queue conn is never closed and the goroutines leak.
func TestServeSessionUnblocksOnTransportClose(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "close-me", Cipher: "chacha20"}

	srvErr := make(chan error, 1)
	go func() {
		_, err := ServeSession(srvT, cfg)
		srvErr <- err
	}()

	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	_ = cliT.Send(append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci)...))
	time.Sleep(200 * time.Millisecond) // arm + enter AcceptKCP

	_ = srvT.Close() // carrier Close with no live session tears down the transport

	select {
	case err := <-srvErr:
		if err == nil {
			t.Fatal("expected ServeSession error after the transport closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSession did not unblock when the transport closed (queue-conn leak)")
	}
}

// TestSessionCloseIsIdempotent guards the teardown path (Close is called from multiple defers).
func TestSessionCloseIsIdempotent(t *testing.T) {
	cliT, srvT := newPipePair(0)
	cfg := SessionConfig{PSK: "k", Cipher: "chacha20"}
	go func() {
		c, err := ServeSession(srvT, cfg)
		if err == nil {
			_ = c.Close()
		}
	}()
	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	go func() { _, _ = cli.Write([]byte("wake")) }() // unblock the server's AcceptKCP
	time.Sleep(200 * time.Millisecond)
	if err := cli.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
