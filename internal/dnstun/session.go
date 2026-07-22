package dnstun

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
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

// Every WireTransport datagram carries a 1-byte kind prefix. All kinds are self-authenticating even if
// flipped: a data/ping/pong parsed as a handshake fails the PSK MAC, and a handshake parsed as sealed
// data fails the AEAD — either way it is dropped, not acted on.
const (
	kindHandshake = 0x00
	kindData      = 0x01
	kindPing      = 0x02 // client -> server sealed keepalive; the server echoes a kindPong
	kindPong      = 0x03 // server -> client sealed keepalive reply
)

// Client keepalive. The client sends a sealed ping every keepalive and re-dials (with a fresh init) if
// it hears nothing authentic for deadWindow — the ONLY way it detects a server that restarted or a
// session the server tore down (KCP's own dead-link never fires on a silent link, and the server keeps
// answering DNS queries even for a mismatched session). Floored generously: this carrier is high-loss,
// so the window must survive several dropped pings without reaping a healthy tunnel.
const keepaliveDeadMult = 3

// Vars (not consts) so a test can shorten them; production keeps these.
var (
	defaultKeepalive   = 10 * time.Second
	keepaliveDeadFloor = 20 * time.Second
)

// SessionConfig carries the crypto parameters both ends share (from the tunnel config), the KCP MTU the
// transport can carry in one datagram (MTU<=0 falls back to kcpMTUDefault), and the client keepalive
// interval (0 falls back to defaultKeepalive).
type SessionConfig struct {
	PSK       string
	Cipher    string
	MTU       int
	Keepalive time.Duration
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
	qpc *QueuePacketConn
	t   WireTransport
	// sealer authenticates the byte stream. It is an atomic.Pointer because the server can SWAP it:
	// when the armed client vanishes before completing KCP and a new client proves itself (a data
	// datagram opens under the staged session), recvPump ADOPTS that session in place so the same
	// AcceptKCP returns the new client — no teardown, no reconnect. sendPump only Loads it. It is
	// Stored once at construction (before the pumps start) and swapped only by recvPump.
	sealer atomic.Pointer[crypto.Sealer]
	// staged is a BOUNDED set of sessions staged by recent different-ephemeral inits (server only).
	// A data datagram that actually OPENS under a candidate proves a real, live new client — a
	// replayed init an attacker captured on-path never can — which then either ADOPTS it in place
	// (while the armed session has never carried data, i.e. its client vanished) or, once the live
	// session is established, TEARS DOWN so the carrier reconnects. A SET (not one slot) so a replayed
	// init can't evict a legit client's staged session by overwriting it; an attacker needs maxStaged
	// DISTINCT captured inits to push it out (was one). Written by onHandshake and read by recvPump,
	// both on the single recvPump goroutine, so it needs no lock.
	staged []stagedSession
	// lastRx is the unix-nano of the last authentic inbound frame (data, ping, or pong). The client's
	// keepalive goroutine ages it against deadWindow to detect a dead/mismatched session and re-dial.
	lastRx    atomic.Int64
	done      chan struct{}
	closeOnce sync.Once
}

// stagedSession is one server-side staged candidate: the client's init ephemeral (so a retransmit of
// the SAME init is re-answered from resp without re-deriving), its derived sealer, and that cached
// handshake response.
type stagedSession struct {
	eInit  [32]byte
	sealer *crypto.Sealer
	resp   []byte
}

// maxStaged bounds the staged-candidate set. Small: on the normal path the set holds one entry, and
// every non-live datagram trial-opens against each entry, so the bound also caps that per-packet work.
const maxStaged = 8

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
			sealed, err := sc.sealer.Load().Seal(dg, nil)
			if err != nil {
				continue
			}
			_ = sc.t.Send(append([]byte{kindData}, sealed...))
		}
	}
}

// recvPump opens inbound datagrams and feeds data plaintext to kcp-go, answers keepalive pings, and
// tracks liveness. onHandshake handles a late/duplicate handshake datagram (the server re-answers a
// retransmitted init; the client ignores it). A datagram that fails to open is dropped in silence.
func (sc *sessionConn) recvPump(inCh <-chan []byte, onHandshake func([]byte)) {
	// liveProven flips true the first time a frame opens under the LIVE sealer — i.e. the live session
	// is established / establishing. It gates promotion of a staged session: adopt-in-place while the
	// armed session is still unproven (its client may have vanished), tear-down once it is established.
	// recvPump-goroutine-local (onHandshake runs inline here too), so it needs no lock.
	liveProven := false
	for {
		select {
		case <-sc.done:
			return
		case d, ok := <-inCh:
			if !ok {
				// The transport died (recvFanout closed inCh). Close the queue conn so a
				// blocked kcp read/AcceptKCP unblocks and the dead session tears down promptly
				// instead of waiting for kcp's dead-link timeout.
				_ = sc.qpc.Close()
				return
			}
			if len(d) < 1 {
				continue
			}
			switch d[0] {
			case kindData:
				if _, _, pt, err := sc.sealer.Load().Open(d[1:], nil); err == nil {
					liveProven = true // a real frame opened under the live session -> it is (being) established
					sc.lastRx.Store(time.Now().UnixNano())
					sc.qpc.QueueIncoming(pt, peerKey)
					continue
				}
				sc.tryStaged(d[1:], true, &liveProven) // a data frame's KCP SYN adopts a proven new client
			case kindPing:
				if _, _, _, err := sc.sealer.Load().Open(d[1:], nil); err == nil {
					liveProven = true
					sc.lastRx.Store(time.Now().UnixNano())
					sc.sendKind(kindPong) // server: echo so the client's keepalive sees a live session
					continue
				}
				sc.tryStaged(d[1:], false, &liveProven) // an idle re-dialed client's ping still forces the tear-down
			case kindPong:
				if _, _, _, err := sc.sealer.Load().Open(d[1:], nil); err == nil {
					sc.lastRx.Store(time.Now().UnixNano()) // client: our keepalive was answered -> session live
				}
			case kindHandshake:
				if onHandshake != nil {
					onHandshake(d[1:])
				}
			}
		}
	}
}

// tryStaged handles a frame the live session couldn't open by trying each staged candidate (server
// only; the set is empty on the client). The first candidate that opens proves a real, live new client
// — a replayed init an attacker captured can never produce such a frame. If the live session has never
// carried data (its client vanished) AND this is a data frame, adopt the new client IN PLACE and feed
// its KCP SYN so the SAME AcceptKCP returns it; once the live session is established, tear down instead
// so the carrier reconnects (an established conv-0 KCP session can't be retrofitted). A proving PING
// pre-establishment has no KCP frame to feed, so it just waits for the client's first data frame.
func (sc *sessionConn) tryStaged(payload []byte, isData bool, liveProven *bool) {
	for i := range sc.staged {
		_, _, pt, perr := sc.staged[i].sealer.Open(payload, nil)
		if perr != nil {
			continue
		}
		switch {
		case *liveProven:
			_ = sc.qpc.Close() // established: tear down -> carrier reconnects and re-accepts the new client
		case isData:
			sc.sealer.Store(sc.staged[i].sealer)
			sc.staged = nil
			*liveProven = true
			sc.lastRx.Store(time.Now().UnixNano())
			sc.qpc.QueueIncoming(pt, peerKey)
		}
		return
	}
}

// sendKind ships a sealed zero-length control frame (a ping or pong) over the transport.
func (sc *sessionConn) sendKind(kind byte) {
	s := sc.sealer.Load()
	if s == nil {
		return
	}
	sealed, err := s.Seal(nil, nil)
	if err != nil {
		return
	}
	_ = sc.t.Send(append([]byte{kind}, sealed...))
}

// keepalive (client only) sends a sealed ping every interval and re-dials — by Closing the session so
// the carrier's Read errors — if nothing authentic has arrived for deadWindow. This is what detects a
// server that restarted or a session the server tore down: the mismatched server can't produce a valid
// pong, so lastRx ages out and the client reconnects with a fresh init. interval/deadWindow are
// resolved by the caller so this goroutine never reads the package tunables (keeps it data-race free).
func (sc *sessionConn) keepalive(interval, deadWindow time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-sc.done:
			return
		case <-t.C:
			sc.sendKind(kindPing)
			if last := sc.lastRx.Load(); last != 0 && time.Since(time.Unix(0, last)) > deadWindow {
				_ = sc.Close() // idempotent; unblocks the carrier read -> reconnect with a fresh init
				return
			}
		}
	}
}

// resolveKeepalive turns the configured interval into (interval, deadWindow), applying the defaults and
// the DNS-carrier floor. Called synchronously in DialSession so the keepalive goroutine holds only
// local copies (no shared read of the package tunables).
func resolveKeepalive(interval time.Duration) (time.Duration, time.Duration) {
	if interval <= 0 {
		interval = defaultKeepalive
	}
	dw := time.Duration(keepaliveDeadMult) * interval
	if dw < keepaliveDeadFloor {
		dw = keepaliveDeadFloor
	}
	return interval, dw
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
	sc := &sessionConn{UDPSession: conn, qpc: qpc, t: t, done: done}
	sc.sealer.Store(sealer) // before the pumps start: sendPump's first Seal must not Load a nil sealer
	sc.lastRx.Store(time.Now().UnixNano())
	kaInterval, kaDeadWindow := resolveKeepalive(cfg.Keepalive)
	go sc.sendPump()
	go sc.recvPump(inCh, nil)                 // client ignores any late handshake datagrams
	go sc.keepalive(kaInterval, kaDeadWindow) // detect a dead/mismatched server and re-dial (client only)
	return sc, nil
}

// ServeSession (server) waits for a valid init on t, derives the session and answers, then
// returns the reliable stream once the client's kcp-go session establishes. It re-answers a
// retransmitted init (same ephemeral) so a lost response self-heals. Single-session: a NEW,
// PSK-authenticated init (client restart) is STAGED and answered but does not replace the live
// session until a datagram actually opens under it — so a replayed old init cannot tear the
// session down (remote DoS). Promotion tears this session down; the carrier owns re-accept.
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
	sc := &sessionConn{qpc: qpc, t: t, done: done}
	sc.sealer.Store(sealer) // before the pumps start (below): sendPump's first Seal must not Load nil
	sc.lastRx.Store(time.Now().UnixNano())
	// Re-answer a retransmit of the SAME init (a lost response self-heals). A DIFFERENT ephemeral
	// might mean the previous client is gone and a new one is dialing (restart) — but it might also
	// be a REPLAYED old init an attacker captured on-path (it still verifies the PSK MAC), so tearing
	// the live session down on sight is a remote DoS. Instead, mirror the datagram carriers'
	// promote-on-open discipline as the single-session design allows: STAGE the new init as a pending
	// session and answer it, but keep the live session running. Only a data datagram that actually
	// opens under a staged candidate (see recvPump) — which a replay can never produce — promotes it
	// and tears the old session down so the carrier reconnects to the new client. Candidates live in a
	// BOUNDED SET (not one slot), so a replayed init can't evict a legit client's staged session by
	// overwriting it. A staged init that re-arrives is re-answered from its cached response without
	// recomputing the (ECDH+KDF) crypto.
	onHS := func(hs []byte) {
		e, err := crypto.ParseInit(cfg.PSK, hs)
		if err != nil {
			return // unauthenticated/garbage init: never touch the live or staged sessions
		}
		if e == gotInit {
			_ = t.Send(respDG) // retransmit of the CURRENT armed init: re-answer, self-heal
			return
		}
		for i := range sc.staged {
			if sc.staged[i].eInit == e {
				_ = t.Send(sc.staged[i].resp) // retransmit of a STAGED init: re-answer without re-deriving
				return
			}
		}
		// A new, PSK-authenticated init: derive + STAGE (do not adopt) a candidate session and answer
		// it. Evict the OLDEST first (FIFO) when the set is full so this newest candidate survives.
		sr, gerr := crypto.GenerateEphemeral()
		if gerr != nil {
			return
		}
		s, serr := crypto.SessionSealer(cfg.Cipher, cfg.PSK, sr, e, e, sr.Pub, false)
		if serr != nil {
			return
		}
		resp := append([]byte{kindHandshake}, crypto.RespMsg(cfg.PSK, e, sr)...)
		if len(sc.staged) >= maxStaged {
			sc.staged = sc.staged[1:]
		}
		sc.staged = append(sc.staged, stagedSession{eInit: e, sealer: s, resp: resp})
		_ = t.Send(resp)
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

// tuneSession applies the DNS-appropriate KCP settings. The carrier is HIGH-LATENCY (hundreds of ms
// per round-trip) and strictly paced at ~one datagram per round-trip by the client's poll loop, so
// the old LAN turbo profile (30ms min-RTO + fast-resend) just fired ~10+ spurious retransmits per
// segment before an ACK could return and never converged. Instead: stream mode (the carrier frames
// its own packets); nodelay OFF so the min-RTO sits at ~100ms and adapts UP to the measured RTT;
// resend=0 to DISABLE fast-retransmit (there are never dup-acks with one datagram in flight); a
// 100ms flush interval matched to the pace; a small window bounding in-flight data to about the
// carrier's bandwidth-delay product; and the MTU the transport carries in one query (<=0 -> default).
func tuneSession(s *kcp.UDPSession, mtu int) {
	if mtu <= 0 {
		mtu = kcpMTUDefault
	}
	s.SetStreamMode(true)
	s.SetNoDelay(0, 100, 0, 1)
	s.SetWindowSize(64, 64)
	s.SetMtu(mtu)
}
