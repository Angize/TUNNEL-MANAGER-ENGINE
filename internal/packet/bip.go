// Package packet implements the "bip" carrier: raw L3 IP packets read from a
// TUN device, framed one-per-datagram, optionally AEAD-sealed, and shipped
// over UDP to the peer, which writes them into its own TUN.
//
// Wire format (one UDP datagram = one frame):
//
//	[0] magic = 0xB1               (legacy framing only; obfs framing has no magic)
//	[1] type  = 0 data | 1 ping | 2 pong
//	[2:] payload — sealed when crypto is on, raw when off
//
// Session establishment. When crypto is on the two ends first run an ephemeral
// X25519 handshake (see crypto.SessionSealer): the client sends a 48-byte init,
// the server replies, and both derive fresh per-session keys. Data flows only
// once that session exists. This gives forward secrecy and makes a captured
// old-session frame undecryptable under the new keys, so it can neither rebind
// the peer nor inject a packet. Handshake messages are demultiplexed from data by
// trial: a datagram that does not AEAD-open under the current session is tried as
// a handshake message (PSK-MAC authenticated); anything that is neither is
// dropped in silence. With crypto off there is no handshake and no authentication
// — a clear-mode tunnel offers no protection against a spoofed frame.
package packet

import (
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	magic byte = 0xB1

	typeData byte = 0
	typePing byte = 1
	typePong byte = 2

	maxDatagram = 65535
)

// Sealer is the subset of crypto.Sealer bip needs. Open returns the authenticated
// (session, seq) pair from the nonce so the carrier can reject replays before
// acting on a frame. aad carries the cleartext frame header (the type byte in
// legacy framing) so it is authenticated and cannot be flipped on the wire; obfs
// framing folds the type into the plaintext and passes nil.
type Sealer interface {
	Seal(pt, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) (session uint64, seq uint64, pt []byte, err error)
}

// sealerBox lets a *crypto.Sealer live in an atomic.Pointer.
type sealerBox struct{ s Sealer }

// Bip carries L3 packets between a TUN device and a UDP peer.
type Bip struct {
	conn      *net.UDPConn
	dev       *tun.Device
	keepalive time.Duration
	obfs      bool
	cryptoOn  bool
	psk       string
	cipher    string
	isClient  bool

	peer    atomic.Pointer[net.UDPAddr]      // current known peer (server learns it)
	session atomic.Pointer[sealerBox]        // negotiated session sealer (nil until handshake / clear mode)
	rp      replayGuard                      // driven only by netToTun (single receiver goroutine)
	pend    *sealerBox                       // server: session staged by a recent init, promoted only once a frame opens under it
	pendRp  replayGuard                      // replay guard for the pending session (adopted on promotion)
	hsCache initCache                        // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci      atomic.Pointer[crypto.Ephemeral] // client's current handshake ephemeral
	lastRx  atomic.Int64                     // unix-nano of the last authenticated frame (client staleness)

	fecEnc *fecEncoder                 // non-nil when FEC is on: buffers data frames into RS blocks on send
	fecDec *fecDecoder                 // non-nil when FEC is on: reassembles + reconstructs blocks on receive
	rxAddr atomic.Pointer[net.UDPAddr] // src of the packet currently feeding fecDec (deliver reads it)

	closeCh   chan struct{}
	closeOnce sync.Once
}

// sessionStale reports that the client has heard nothing it could authenticate from the server
// for long enough that the peer has most likely restarted with a fresh session. The client then
// drops its now-useless session and re-handshakes. Without this a SERVER restart wedges the tunnel:
// the client keeps pinging under a key the fresh server cannot open and — because it still holds a
// session — never re-initiates on its own. A false positive (a few lost pings on a healthy link)
// only costs one harmless re-handshake. Only meaningful with crypto on.
func (b *Bip) sessionStale() bool {
	last := b.lastRx.Load()
	if last == 0 {
		return false // no baseline yet
	}
	w := 3 * b.keepalive
	if w < 10*time.Second {
		w = 10 * time.Second
	}
	return time.Since(time.Unix(0, last)) > w
}

// Dial (client role) binds an ephemeral UDP socket and targets peerAddr.
func Dial(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int) (*Bip, error) {
	ra, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil) // ephemeral local port
	if err != nil {
		return nil, err
	}
	b := &Bip{conn: conn, dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, isClient: true, closeCh: make(chan struct{})}
	b.peer.Store(ra)
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

// Listen (server role) binds listenAddr and waits to learn the peer.
func Listen(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int) (*Bip, error) {
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	b := &Bip{conn: conn, dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, closeCh: make(chan struct{})}
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

// initFec wires the FEC encoder/decoder (no-op when fec is off). Data shards emit to
// the current peer; recovered frames re-enter the normal receive path with the source
// of the packet that completed their block.
func (b *Bip) initFec(fec bool, fecData, fecParity int) {
	b.fecEnc, b.fecDec = newFecPair(fec, fecData, fecParity, "bip",
		func(pkt []byte) {
			if p := b.peer.Load(); p != nil {
				_, _ = b.conn.WriteToUDP(pkt, p)
			}
		},
		func(frame []byte) { b.deliver(frame, b.rxAddr.Load()) })
}

// Run blocks until one of the loops fails (e.g. the socket or device closes).
func (b *Bip) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- b.tunToNet() }()
	go func() { errc <- b.netToTun() }()
	if b.isClient {
		go b.clientLoop()
	}
	return <-errc
}

// Close tears down the socket (which unblocks both loops) and stops the client
// loop. Safe to call more than once.
func (b *Bip) Close() error {
	b.closeOnce.Do(func() { close(b.closeCh) })
	if b.fecEnc != nil {
		b.fecEnc.Close() // stop the FEC flush timer before the socket goes away
	}
	return b.conn.Close()
}

func (b *Bip) sealer() Sealer {
	if box := b.session.Load(); box != nil {
		return box.s
	}
	return nil
}

// frame builds one datagram for typ/payload using the current session sealer
// (or clear framing when crypto is off / no session yet).
func (b *Bip) frame(typ byte, payload []byte) ([]byte, error) {
	s := b.sealer()
	if b.obfs {
		return obfsSeal(s, typ, payload, padMaxFor(typ))
	}
	if s != nil {
		sealed, err := s.Seal(payload, []byte{typ}) // authenticate the type byte
		if err != nil {
			return nil, err
		}
		out := make([]byte, 2+len(sealed))
		out[0], out[1] = magic, typ
		copy(out[2:], sealed)
		return out, nil
	}
	out := make([]byte, 2+len(payload))
	out[0], out[1] = magic, typ
	copy(out[2:], payload)
	return out, nil
}

// tunToNet reads L3 packets from TUN, seals them, and sends to the peer. Packets
// read before a session exists (crypto on, handshake not yet complete) are
// dropped; the peer retransmits at L4.
func (b *Bip) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := b.peer.Load()
		if peer == nil {
			continue // server has not learned the client yet; drop
		}
		if b.cryptoOn && b.sealer() == nil {
			continue // handshake not finished yet; drop (L4 will retransmit)
		}
		frame, err := b.frame(typeData, buf[:n])
		if err != nil {
			log.Printf("bip: seal error: %v", err)
			continue
		}
		if b.fecEnc != nil {
			b.fecEnc.addData(frame) // buffered into an RS block; shards go out via the emit callback
			continue
		}
		if _, err := b.conn.WriteToUDP(frame, peer); err != nil {
			log.Printf("bip: write error: %v", err)
		}
	}
}

// netToTun receives datagrams, authenticates them, rejects replays, updates the
// known peer, and writes data frames into the TUN. Datagrams that do not open
// under the current session are tried as handshake messages.
func (b *Bip) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if b.fecDec != nil {
			// netToTun is the sole reader, so rxAddr is stable for the whole input()
			// call (the decoder delivers recovered frames synchronously within it).
			b.rxAddr.Store(addr)
			b.fecDec.input(buf[:n])
			continue
		}
		b.deliver(buf[:n], addr)
	}
}

// deliver dispatches one received frame (already de-FEC'd): authenticated data in
// crypto mode, or unauthenticated legacy framing in clear mode.
func (b *Bip) deliver(pkt []byte, addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	if b.cryptoOn {
		b.handleCrypto(pkt, addr)
		return
	}
	if len(pkt) < 2 || pkt[0] != magic {
		return
	}
	b.peer.Store(addr)
	b.dispatch(pkt[1], iff(pkt[1] == typeData, pkt[2:], nil), addr)
}

// openWith tries to open one datagram under a specific session sealer, returning the
// authenticated frame. It touches no session/replay state, so a frame can safely be tried
// against both the live and a pending session.
func (b *Bip) openWith(s Sealer, pkt []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	if b.obfs {
		return obfsOpen(s, pkt)
	}
	if len(pkt) >= 2 && pkt[0] == magic {
		typ = pkt[1]
		session, seq, payload, oerr = s.Open(pkt[2:], []byte{typ})
		return
	}
	return 0, 0, 0, nil, errBadFrame
}

// handleCrypto is the crypto-on receive path: try the frame as data under the current
// session; failing that, under a pending session staged by a recent init (promoting it if
// it opens); failing that, as a handshake message.
func (b *Bip) handleCrypto(pkt []byte, addr *net.UDPAddr) {
	if s := b.sealer(); s != nil {
		if typ, session, seq, payload, oerr := b.openWith(s, pkt); oerr == nil && b.rp.ok(session, seq) {
			// authenticated, fresh frame -> now safe to (re)learn the peer address
			b.lastRx.Store(time.Now().UnixNano()) // liveness: the session is answering
			b.peer.Store(addr)
			b.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a PENDING session
	// staged by a recent init. Only a frame that actually opens under it promotes it (and
	// rebinds the peer), so a replayed init — which stages a session an attacker cannot
	// produce a frame for — never tears down the live session or resets its replay window.
	if b.pend != nil {
		if typ, session, seq, payload, oerr := b.openWith(b.pend.s, pkt); oerr == nil && b.pendRp.ok(session, seq) {
			b.session.Store(b.pend)
			b.rp = b.pendRp
			b.pend = nil
			b.lastRx.Store(time.Now().UnixNano())
			b.peer.Store(addr)
			b.dispatch(typ, payload, addr)
			return
		}
	}
	b.tryHandshake(pkt, addr)
}

// tryHandshake demuxes a datagram that did not open as data. On the server an
// init starts a fresh session; on the client a resp completes ours.
func (b *Bip) tryHandshake(pkt []byte, addr *net.UDPAddr) {
	if b.isClient {
		ci := b.ci.Load()
		if ci == nil {
			return
		}
		eResp, err := crypto.ParseResp(b.psk, ci.Pub, pkt)
		if err != nil {
			return
		}
		s, err := crypto.SessionSealer(b.cipher, b.psk, ci, eResp, ci.Pub, eResp, true)
		if err != nil {
			return
		}
		b.rp = replayGuard{}
		b.session.Store(&sealerBox{s: s})
		b.lastRx.Store(time.Now().UnixNano()) // baseline so the fresh session isn't instantly "stale"
		return
	}
	// server: authenticate an init, reply, and install the fresh session.
	// Compute-DoS mitigation: an attacker replaying captured valid inits at high rate
	// would otherwise force a fresh ECDH+HKDF (GenerateEphemeral+SessionSealer) per packet.
	// If this init matches one we recently answered (while a pending session is current),
	// just re-send the response we already computed and return before that expensive
	// crypto. The handshake outcome is unchanged (pend/promote-on-open is untouched); a
	// genuinely new init falls through to the full handshake below. The cache is a small
	// LRU (not a single entry) so alternating two captured inits cannot bust it. It is
	// touched only on this single receive goroutine (like pend/rp), so no locking is needed.
	if b.pend != nil {
		if resp, ok := b.hsCache.get(pkt); ok {
			b.writeCtrl(resp, addr)
			return
		}
	}
	eInit, err := crypto.ParseInit(b.psk, pkt)
	if err != nil {
		return
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	s, err := crypto.SessionSealer(b.cipher, b.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return
	}
	// Stage the new session as PENDING rather than swapping it in now. The live session and
	// its replay window stay intact until a frame actually opens under these new keys (see
	// handleCrypto), so a replayed init cannot wedge the tunnel by resetting them. Rebinding
	// the peer is likewise deferred to that first opening frame.
	b.pend = &sealerBox{s: s}
	b.pendRp = replayGuard{}
	if msg2 := crypto.RespMsg(b.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while pend is
		// still current) is served without recomputing the crypto above. put copies pkt
		// (it aliases the receive buffer); msg2 is a fresh slice, safe to keep.
		b.hsCache.put(pkt, msg2)
		b.writeCtrl(msg2, addr)
	}
}

// writeCtrl sends a control/handshake datagram, tagging it passthrough under FEC so
// the peer's decoder forwards it straight through (never held in a block or parsed as
// a shard). to may differ from the learned peer (a server's handshake reply).
func (b *Bip) writeCtrl(pkt []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	_, _ = b.conn.WriteToUDP(fecTag(b.fecEnc, pkt), to)
}

func (b *Bip) dispatch(typ byte, payload []byte, addr *net.UDPAddr) {
	switch typ {
	case typePing:
		b.send(typePong, nil, addr)
	case typePong:
		// keepalive ack
	case typeData:
		if _, err := b.dev.Write(payload); err != nil {
			log.Printf("bip: tun write error: %v", err)
		}
	}
}

// clientLoop (client) drives the handshake and keepalives: it (re)sends an init
// until a session exists, then pings on a jittered interval. If the session is
// lost it starts a new handshake.
func (b *Bip) clientLoop() {
	for {
		if b.cryptoOn && b.sealer() != nil && b.sessionStale() {
			b.session.Store(nil) // server likely restarted — drop the dead session so we re-handshake
			b.ci.Store(nil)
			log.Print("bip: no reply from the peer's session — re-handshaking (peer likely restarted)")
		}
		if b.sealer() == nil && b.cryptoOn {
			b.sendInit()
		} else {
			b.send(typePing, nil, b.peer.Load())
		}
		wait := b.keepalive
		if b.sealer() == nil && b.cryptoOn {
			wait = time.Second // retransmit the handshake faster than keepalive
		} else {
			wait = jitter(wait)
		}
		select {
		case <-b.closeCh:
			return
		case <-time.After(wait):
		}
	}
}

func (b *Bip) sendInit() {
	peer := b.peer.Load()
	if peer == nil {
		return
	}
	// Reuse the current ephemeral across retransmits — regenerate ONLY to start a fresh
	// handshake cycle (ci==nil: first attempt, or after a stale-session reset). Regenerating
	// every 1s retransmit would race the reply: on a link whose init->resp RTT exceeds the
	// retransmit interval, the response (checked against the CURRENT ci) would always verify
	// against a newer ephemeral and be dropped, so the handshake could never complete.
	ci := b.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		b.ci.Store(ci)
	}
	b.writeCtrl(crypto.InitMsg(b.psk, ci), peer)
}

func (b *Bip) send(typ byte, payload []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	if b.cryptoOn && b.sealer() == nil {
		return // no session yet
	}
	frame, err := b.frame(typ, payload)
	if err != nil {
		return
	}
	b.writeCtrl(frame, to)
}

func iff(cond bool, a, b []byte) []byte {
	if cond {
		return a
	}
	return b
}

var errBadFrame = errors.New("bip: bad frame")

// ErrClosed is returned by Run when the connection was closed intentionally.
var ErrClosed = errors.New("bip: closed")
