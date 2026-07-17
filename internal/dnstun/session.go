package dnstun

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	kcp "github.com/xtaci/kcp-go/v5"
)

// WireTransport ships opaque, unreliable datagrams to and from the ONE peer. The DNS carrier
// implements it over DNS queries/responses (client) or an authoritative responder (server);
// tests drive it with an in-memory lossy pipe. Send is best-effort — a datagram may be lost or
// reordered. Recv blocks for the next inbound datagram and returns an error once the transport
// is closed. The reliability and ordering the tunnel needs are supplied ABOVE this by kcp-go.
type WireTransport interface {
	Send(datagram []byte) error
	Recv() ([]byte, error)
	Close() error
}

// Every WireTransport datagram carries a 1-byte kind prefix. The two kinds are self-
// authenticating even if flipped: a data datagram parsed as a handshake fails the PSK MAC, and
// a handshake datagram parsed as data fails the AEAD — either way it is dropped, not acted on.
const (
	kindHandshake = 0x00
	kindData      = 0x01
)

// SessionConfig carries the crypto parameters both ends share (from the tunnel config) plus the
// KCP MTU the transport can carry in one datagram. MTU<=0 falls back to kcpMTUDefault.
type SessionConfig struct {
	PSK    string
	Cipher string
	MTU    int
}

// peerKey is the single logical peer identity on both ends' QueuePacketConn. The tunnel is
// point-to-point (one client ⇄ one server), so a fixed key suffices; it is never on the wire.
var peerKey = ClientID{0xD1, 0x5C, 0xA5, 0x5E, 0x55, 0x10, 0x0A, 0x1D}

// kcpMTUDefault bounds a KCP datagram when the caller doesn't compute one. The DNS transport
// derives the real value from the query-name budget (codec.MaxUpstream minus AEAD/kind overhead)
// so every KCP datagram rides exactly one DNS query.
const kcpMTUDefault = 220

// SessionOverhead is the per-datagram cost the DNS transport must subtract from the codec's
// MaxUpstream to get the KCP MTU: the 1-byte kind prefix plus AEAD sealing (12-byte mask salt +
// up to a 24-byte nonce + 16-byte tag). A few bytes of slack keeps xchacha (24-byte nonce) safe.
const SessionOverhead = 1 + 12 + 24 + 16 + 3

const handshakeRetxInterval = 500 * time.Millisecond

// handshakeTimeout is a var (not const) only so a test can shorten it; production keeps 15s,
// generous for a slow DNS channel where a lost init/resp costs a full retransmit interval.
var handshakeTimeout = 15 * time.Second

// sessionConn is the reliable, AEAD-authenticated byte stream the carrier reads/writes. It is a
// net.Conn (the kcp-go session) whose Close also tears down the seal pumps, queue conn and
// transport. The carrier frames tunnel packets over it.
type sessionConn struct {
	*kcp.UDPSession
	qpc       *QueuePacketConn
	t         WireTransport
	sealer    *crypto.Sealer
	done      chan struct{}
	closeOnce sync.Once
}

// Close tears down the whole session exactly once, unblocking every loop. UDPSession may be nil
// on a server error path (AcceptKCP failed before it was set), so it is guarded. Closing t makes
// the transport's Recv return, which stops recvFanout.
func (sc *sessionConn) Close() error {
	sc.closeOnce.Do(func() {
		close(sc.done)
		if sc.UDPSession != nil {
			_ = sc.UDPSession.Close()
		}
		_ = sc.qpc.Close()
		_ = sc.t.Close()
	})
	return nil
}

// recvFanout reads the transport and fans datagrams onto inCh until the session closes or the
// transport dies. One reader keeps the handshake step and the data pump from racing on Recv.
func recvFanout(t WireTransport, inCh chan<- []byte, done <-chan struct{}) {
	for {
		d, err := t.Recv()
		if err != nil {
			close(inCh)
			return
		}
		select {
		case inCh <- d:
		case <-done:
			return
		}
	}
}

// sendPump drains kcp-go's outgoing datagrams, AEAD-seals each, and ships it over the transport.
func (sc *sessionConn) sendPump() {
	out := sc.qpc.OutgoingQueue(peerKey)
	for {
		select {
		case <-sc.done:
			return
		case dg := <-out:
			sealed, err := sc.sealer.Seal(dg, nil)
			if err != nil {
				continue
			}
			_ = sc.t.Send(append([]byte{kindData}, sealed...))
		}
	}
}

// recvPump opens inbound data datagrams and feeds the plaintext to kcp-go. onHandshake handles a
// late/duplicate handshake datagram (the server re-answers a retransmitted init; the client
// ignores it). A datagram that fails to open is dropped in silence.
func (sc *sessionConn) recvPump(inCh <-chan []byte, onHandshake func([]byte)) {
	for {
		select {
		case <-sc.done:
			return
		case d, ok := <-inCh:
			if !ok {
				return
			}
			if len(d) < 1 {
				continue
			}
			switch d[0] {
			case kindData:
				_, _, pt, err := sc.sealer.Open(d[1:], nil)
				if err != nil {
					continue
				}
				sc.qpc.QueueIncoming(pt, peerKey)
			case kindHandshake:
				if onHandshake != nil {
					onHandshake(d[1:])
				}
			}
		}
	}
}

// DialSession (client) runs the X25519 handshake over t (retransmitting the init until the
// responder answers or the deadline passes), then returns a reliable, AEAD-authenticated stream
// to the server. The caller must Close the returned conn to release the transport and goroutines.
func DialSession(t WireTransport, cfg SessionConfig) (net.Conn, error) {
	done := make(chan struct{})
	inCh := make(chan []byte, 256)
	go recvFanout(t, inCh, done)

	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		close(done)
		_ = t.Close()
		return nil, err
	}
	initDG := append([]byte{kindHandshake}, crypto.InitMsg(cfg.PSK, ci)...)
	_ = t.Send(initDG)

	var sealer *crypto.Sealer
	deadline := time.NewTimer(handshakeTimeout)
	defer deadline.Stop()
	retx := time.NewTicker(handshakeRetxInterval)
	defer retx.Stop()
handshake:
	for {
		select {
		case <-deadline.C:
			close(done)
			_ = t.Close()
			return nil, errors.New("dns session: handshake timed out")
		case <-retx.C:
			_ = t.Send(initDG) // the transport is lossy — resend until answered
		case d, ok := <-inCh:
			if !ok {
				close(done)
				_ = t.Close()
				return nil, errors.New("dns session: transport closed during handshake")
			}
			if len(d) < 1 || d[0] != kindHandshake {
				continue
			}
			eResp, perr := crypto.ParseResp(cfg.PSK, ci.Pub, d[1:])
			if perr != nil {
				continue
			}
			s, serr := crypto.SessionSealer(cfg.Cipher, cfg.PSK, ci, eResp, ci.Pub, eResp, true)
			if serr != nil {
				close(done)
				_ = t.Close()
				return nil, serr
			}
			sealer = s
			break handshake
		}
	}

	qpc := NewQueuePacketConn(peerKey)
	conn, err := kcp.NewConn2(peerKey, nil, 0, 0, qpc)
	if err != nil {
		close(done)
		_ = qpc.Close()
		_ = t.Close()
		return nil, err
	}
	tuneSession(conn, cfg.MTU)
	sc := &sessionConn{UDPSession: conn, qpc: qpc, t: t, sealer: sealer, done: done}
	go sc.sendPump()
	go sc.recvPump(inCh, nil) // client ignores any late handshake datagrams
	return sc, nil
}

// ServeSession (server) waits for a valid init on t, derives the session and answers, then
// returns the reliable stream once the client's kcp-go session establishes. It re-answers a
// retransmitted init (same ephemeral) so a lost response self-heals. Single-session: a NEW init
// (client restart) is ignored until this session is closed — the carrier owns re-accept.
func ServeSession(t WireTransport, cfg SessionConfig) (net.Conn, error) {
	done := make(chan struct{})
	inCh := make(chan []byte, 256)
	go recvFanout(t, inCh, done)

	var (
		sealer  *crypto.Sealer
		respDG  []byte
		gotInit [32]byte
	)
	for sealer == nil {
		d, ok := <-inCh
		if !ok {
			close(done)
			_ = t.Close()
			return nil, errors.New("dns session: transport closed before handshake")
		}
		if len(d) < 1 || d[0] != kindHandshake {
			continue
		}
		eInit, perr := crypto.ParseInit(cfg.PSK, d[1:])
		if perr != nil {
			continue
		}
		sr, gerr := crypto.GenerateEphemeral()
		if gerr != nil {
			close(done)
			_ = t.Close()
			return nil, gerr
		}
		s, serr := crypto.SessionSealer(cfg.Cipher, cfg.PSK, sr, eInit, eInit, sr.Pub, false)
		if serr != nil {
			close(done)
			_ = t.Close()
			return nil, serr
		}
		sealer, gotInit = s, eInit
		respDG = append([]byte{kindHandshake}, crypto.RespMsg(cfg.PSK, eInit, sr)...)
		_ = t.Send(respDG)
	}

	qpc := NewQueuePacketConn(peerKey)
	sc := &sessionConn{qpc: qpc, t: t, sealer: sealer, done: done}
	// Re-answer only a retransmit of the SAME init; a different ephemeral is a new session we
	// do not adopt here (would swap keys mid-stream), so it is ignored.
	onHS := func(hs []byte) {
		if e, err := crypto.ParseInit(cfg.PSK, hs); err == nil && e == gotInit {
			_ = t.Send(respDG)
		}
	}
	go sc.sendPump()
	go sc.recvPump(inCh, onHS)

	lis, err := kcp.ServeConn(nil, 0, 0, qpc)
	if err != nil {
		sc.Close()
		return nil, err
	}
	conn, err := lis.AcceptKCP() // returns once the client's first KCP datagram arrives
	if err != nil {
		sc.Close()
		return nil, err
	}
	tuneSession(conn, cfg.MTU)
	sc.UDPSession = conn
	return sc, nil
}

// tuneSession applies the DNS-appropriate KCP settings: turbo mode (fast retransmit) for quick
// recovery on a lossy channel, stream mode (the carrier frames its own packets), a small window,
// and the MTU the transport can carry in one datagram (mtu<=0 falls back to the default).
func tuneSession(s *kcp.UDPSession, mtu int) {
	if mtu <= 0 {
		mtu = kcpMTUDefault
	}
	s.SetStreamMode(true)
	s.SetNoDelay(1, 20, 2, 1)
	s.SetWindowSize(256, 256)
	s.SetMtu(mtu)
}
