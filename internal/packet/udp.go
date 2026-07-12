// Package packet implements the core carrier: raw L3 IP packets read from a
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

// Sealer is the subset of crypto.Sealer core needs. Open returns the authenticated
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

// UDP carries L3 packets between a TUN device and a UDP peer.
type UDP struct {
	// conn is the live socket. It is an atomic pointer (not a plain *net.UDPConn) because a source-IP
	// rotation rebinds it: rotateSourceUDP opens a fresh socket on the new source IP, swaps it in, and
	// closes the old one. rebindGen is bumped on every deliberate rebind so the receive loop can tell a
	// rotation-induced ReadFromUDP error (reload the new conn and keep going) from a real socket death.
	conn      atomic.Pointer[net.UDPConn]
	rebindGen atomic.Int64
	rebindMu  sync.Mutex // serializes rebindSourceTo so a proactive rotation and a pin-poll adopt can't race the swap (double-close / socket leak)
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

	st *coreStatus // client-only: precise self-heal event ring written to the status file (nil = off)
	pp *PeerPool   // client-only: destination-IP rotation pool (nil = single fixed peer, no rotation)
	sp *PeerPool   // client-only: source-IP rotation pool (nil = fixed source; rebinds the socket on rotate)
}

// SetPeerPool (client, direct transports) wires a destination-IP rotation pool: when the current
// peer looks dead (its handshake never completes) the client burns it and re-points at the next
// live endpoint, and a proactive timer also rotates. nil / single-endpoint pool = no rotation. main
// wires it via the shared SetPeerPool type assertion. Call before Run().
func (b *UDP) SetPeerPool(pp *PeerPool) {
	if b.isClient {
		b.pp = pp
	}
}

// peerFailThreshold is how many ~1s handshake retransmits with no session go by before the client
// concludes the current peer is dead and rotates to the next pool endpoint (crypto on). Long enough
// to ride out a slow handshake / brief loss, short enough to fail over from a blocked IP quickly.
const peerFailThreshold = 12

// rotatePeerUDP points the client at the next pool endpoint: burn+advance (proactive=false) or a
// timed rotate (proactive=true). It resolves the endpoint and swaps b.peer, then clears the session
// so the next loop re-handshakes against the new destination. No-op when the pool did not move.
func (b *UDP) rotatePeerUDP(proactive bool) {
	if b.pp == nil {
		return
	}
	var addr string
	var moved bool
	if proactive {
		addr, moved = b.pp.rotateOnce()
	} else {
		addr, moved = b.pp.fail()
	}
	if !moved {
		return
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil || ua == nil {
		return
	}
	b.peer.Store(ua)
	b.session.Store(nil) // force a fresh handshake to the new destination
	b.ci.Store(nil)
	log.Printf("core/udp: rotated destination to %s", addr)
	b.st.down("peer-rotate", "udp")
}

// SetSourcePool (client) wires a source-IP rotation pool: the client cycles the local IP it sends
// FROM. Unlike raw/flux (which stamp the source per packet), udp owns a kernel socket, so a rotation
// REBINDS it — a fresh socket on the new source IP replaces the old one (see rotateSourceUDP). The
// AEAD session is independent of the address, so the session survives; the server just relearns the
// peer from the next authenticated frame. nil / single-endpoint = fixed source. Call before Run().
func (b *UDP) SetSourcePool(sp *PeerPool) {
	if !b.isClient {
		return
	}
	b.sp = sp
	// Bind the initial socket to the pool's first source so the client egresses from SrcIPs[0]
	// immediately (matching the pool's cur=0), instead of the OS-default source until the first
	// rotation — which on a failover-only pool (rotate=0) would otherwise never happen. Called before
	// Run(), so there is no receive loop yet: a plain swap (no rebindGen dance) is safe here.
	if sp != nil {
		host := sp.current()
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			if nc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip}); err == nil {
				old := b.conn.Load()
				b.conn.Store(nc)
				if old != nil {
					_ = old.Close()
				}
			}
		}
	}
}

// rotateSourceUDP rebinds the socket onto the next source-pool IP. It does NOT touch the session (the
// source is independent of the AEAD keys), so no re-handshake: the client keeps sending under the same
// session from the new local address and the server follows. No-op when the pool did not move or the
// new socket can't bind (e.g. the IP isn't local) — the old socket stays live.
func (b *UDP) rotateSourceUDP(proactive bool) {
	if b.sp == nil {
		return
	}
	var addr string
	var moved bool
	if proactive {
		addr, moved = b.sp.rotateOnce()
	} else {
		addr, moved = b.sp.fail()
	}
	if !moved {
		return
	}
	if host, ok := b.rebindSourceTo(addr); ok {
		log.Printf("core/udp: rotated source to %s", host)
		b.st.down("src-rotate", "udp")
	}
}

// rebindSourceTo opens a fresh socket on the given source IP (bare or ip:port) and swaps it in for the
// live one, returning the bound host and whether it happened. Shared by proactive/failover rotation and
// the operator source pin. No-op / false when the IP can't be parsed or bound (the old socket stays live).
func (b *UDP) rebindSourceTo(addr string) (string, bool) {
	host := addr
	if h, _, e := net.SplitHostPort(addr); e == nil { // tolerate an accidental ip:port
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	b.rebindMu.Lock() // serialize the load/store/gen-bump/close so a concurrent rebind can't leak or double-close
	defer b.rebindMu.Unlock()
	nc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip}) // fresh socket on the new source (ephemeral port)
	if err != nil {
		log.Printf("core/udp: source rebind to %s failed: %v", host, err)
		return "", false
	}
	old := b.conn.Load()
	// Order matters (netToTun loads gen THEN conn): store the new conn BEFORE bumping the gen. Then any
	// reader that still loaded the OLD conn must have sampled its gen BEFORE this bump (Go atomics are
	// sequentially consistent), so its post-error re-check sees the bumped gen and continues instead of
	// misreading the deliberate swap as a socket death. Bumping before the store reopens that race.
	b.conn.Store(nc)
	b.rebindGen.Add(1)
	_ = old.Close() // unblocks netToTun's ReadFromUDP; it reloads nc via rebindGen and continues
	return host, true
}

// adoptPeerUDP re-points the client at the pool's CURRENT destination — used when an operator pin has
// just jumped the pool to a chosen endpoint — and clears the session so the next loop re-handshakes there.
func (b *UDP) adoptPeerUDP() {
	if b.pp == nil {
		return
	}
	addr := b.pp.current()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil || ua == nil {
		return
	}
	b.peer.Store(ua)
	b.session.Store(nil)
	b.ci.Store(nil)
	log.Printf("core/udp: pinned destination to %s", addr)
	b.st.down("peer-pin", "udp")
}

// adoptSourceUDP rebinds the socket onto the pool's CURRENT source (an operator source pin). Safe from
// the pin-poll goroutine: a pin freezes rotation (rotationController.pinned), so rotateSourceUDP cannot
// be rebinding concurrently.
func (b *UDP) adoptSourceUDP() {
	if b.sp == nil {
		return
	}
	addr := b.sp.current()
	if host, ok := b.rebindSourceTo(addr); ok {
		log.Printf("core/udp: pinned source to %s", host)
		b.st.down("src-pin", "udp")
	}
}

// ProbeAllNow retests every suspect/dead endpoint on both pools at once (the panel "probe now" control,
// delivered as SIGHUP). No-op unless pooled.
func (b *UDP) ProbeAllNow() {
	if b.pp != nil {
		b.pp.probeAllNow()
	}
	if b.sp != nil {
		b.sp.probeAllNow()
	}
}

// pinPollLoop polls the pools' cmd files on a 1s ticker and applies any operator pin. Runs until Close.
func (b *UDP) pinPollLoop(rc *rotationController) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			rc.pollPins(b.adoptPeerUDP, b.adoptSourceUDP)
		}
	}
}

// SetStatusPath (client, optional) wires a status-file event ring so self-heal re-handshakes and
// recoveries surface in the panel's system log. Call before Run(). No-op path leaves it off.
func (b *UDP) SetStatusPath(path string) {
	if path == "" || !b.isClient {
		return
	}
	peer := ""
	if p := b.peer.Load(); p != nil {
		peer = p.String()
	}
	b.st = newCoreStatus(path, "udp · "+peer)
}

// sessionStale reports that the client has heard nothing it could authenticate from the server
// for long enough that the peer has most likely restarted with a fresh session. The client then
// drops its now-useless session and re-handshakes. Without this a SERVER restart wedges the tunnel:
// the client keeps pinging under a key the fresh server cannot open and — because it still holds a
// session — never re-initiates on its own. A false positive (a few lost pings on a healthy link)
// only costs one harmless re-handshake. Only meaningful with crypto on.
func (b *UDP) sessionStale() bool {
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
func Dial(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int) (*UDP, error) {
	ra, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil) // ephemeral local port
	if err != nil {
		return nil, err
	}
	b := &UDP{dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, isClient: true, closeCh: make(chan struct{})}
	b.conn.Store(conn)
	b.peer.Store(ra)
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

// Listen (server role) binds listenAddr and waits to learn the peer.
func Listen(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int) (*UDP, error) {
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	b := &UDP{dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, closeCh: make(chan struct{})}
	b.conn.Store(conn)
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

// initFec wires the FEC encoder/decoder (no-op when fec is off). Data shards emit to
// the current peer; recovered frames re-enter the normal receive path with the source
// of the packet that completed their block.
func (b *UDP) initFec(fec bool, fecData, fecParity int) {
	b.fecEnc, b.fecDec = newFecPair(fec, fecData, fecParity, "udp",
		func(pkt []byte) {
			if p := b.peer.Load(); p != nil {
				_, _ = b.conn.Load().WriteToUDP(pkt, p)
			}
		},
		func(frame []byte) { b.deliver(frame, b.rxAddr.Load()) })
}

// Run blocks until one of the loops fails (e.g. the socket or device closes).
func (b *UDP) Run() error {
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
func (b *UDP) Close() error {
	b.closeOnce.Do(func() { close(b.closeCh) })
	if b.fecEnc != nil {
		b.fecEnc.Close() // stop the FEC flush timer before the socket goes away
	}
	return b.conn.Load().Close()
}

func (b *UDP) sealer() Sealer {
	if box := b.session.Load(); box != nil {
		return box.s
	}
	return nil
}

// frame builds one datagram for typ/payload using the current session sealer
// (or clear framing when crypto is off / no session yet).
func (b *UDP) frame(typ byte, payload []byte) ([]byte, error) {
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
func (b *UDP) tunToNet() error {
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
			log.Printf("core: seal error: %v", err)
			continue
		}
		if b.fecEnc != nil {
			b.fecEnc.addData(frame) // buffered into an RS block; shards go out via the emit callback
			continue
		}
		if _, err := b.conn.Load().WriteToUDP(frame, peer); err != nil {
			log.Printf("core: write error: %v", err)
		}
	}
}

// netToTun receives datagrams, authenticates them, rejects replays, updates the
// known peer, and writes data frames into the TUN. Datagrams that do not open
// under the current session are tried as handshake messages.
func (b *UDP) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		gen := b.rebindGen.Load()
		n, addr, err := b.conn.Load().ReadFromUDP(buf)
		if err != nil {
			// A source rotation closes the old socket out from under this read. Distinguish that
			// deliberate swap (gen advanced) — reload the new socket and keep going — from a genuine
			// socket death (gen unchanged), which ends the loop as before.
			if b.rebindGen.Load() != gen {
				continue
			}
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
func (b *UDP) deliver(pkt []byte, addr *net.UDPAddr) {
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
	if b.pp == nil { // a pooled client owns its peer (mirror the crypto path); a server always learns it
		b.peer.Store(addr)
	}
	b.dispatch(pkt[1], iff(pkt[1] == typeData, pkt[2:], nil), addr)
}

// openWith tries to open one datagram under a specific session sealer, returning the
// authenticated frame. It touches no session/replay state, so a frame can safely be tried
// against both the live and a pending session.
func (b *UDP) openWith(s Sealer, pkt []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
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
func (b *UDP) handleCrypto(pkt []byte, addr *net.UDPAddr) {
	if s := b.sealer(); s != nil {
		if typ, session, seq, payload, oerr := b.openWith(s, pkt); oerr == nil && b.rp.ok(session, seq) {
			// authenticated, fresh frame -> now safe to (re)learn the peer address
			b.lastRx.Store(time.Now().UnixNano()) // liveness: the session is answering
			// The DESTINATION pool owns the client's peer: don't rebind it from a reply's source. A
			// pool server may listen on 0.0.0.0 and answer from its default egress IP (≠ the IP the
			// client dialed); adopting that would silently pull the client off the endpoint the pool
			// is rotating. Servers (pp==nil) still learn the client here — which is what lets them
			// follow a client's SOURCE rotation.
			if b.pp == nil {
				b.peer.Store(addr)
			}
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
func (b *UDP) tryHandshake(pkt []byte, addr *net.UDPAddr) {
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
		b.st.reconnected("udp")               // recovery after a self-heal (nil-safe; silent on first connect)
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
func (b *UDP) writeCtrl(pkt []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	_, _ = b.conn.Load().WriteToUDP(fecTag(b.fecEnc, pkt), to)
}

func (b *UDP) dispatch(typ byte, payload []byte, addr *net.UDPAddr) {
	switch typ {
	case typePing:
		b.send(typePong, nil, addr)
	case typePong:
		// keepalive ack
	case typeData:
		if _, err := b.dev.Write(payload); err != nil {
			log.Printf("core: tun write error: %v", err)
		}
	}
}

// clientLoop (client) drives the handshake and keepalives: it (re)sends an init
// until a session exists, then pings on a jittered interval. If the session is
// lost it starts a new handshake.
func (b *UDP) clientLoop() {
	failN := 0 // consecutive handshake retransmits with no session -> the peer may be dead
	rc := newRotationController(b.pp, b.sp)
	if rc.active() {
		go b.pinPollLoop(rc)
	}
	for {
		if b.cryptoOn && b.sealer() != nil && b.sessionStale() {
			b.session.Store(nil) // server likely restarted — drop the dead session so we re-handshake
			b.ci.Store(nil)
			log.Print("core: no reply from the peer's session — re-handshaking (peer likely restarted)")
			b.st.down("stale", "udp") // precise reason for the panel log (nil-safe when off)
		}
		if b.sealer() == nil && b.cryptoOn {
			b.sendInit()
			if failN++; rc.active() && failN >= peerFailThreshold {
				rc.fail(b.rotatePeerUDP, b.rotateSourceUDP) // burn+advance dest; walk source once dests cycle
				failN = 0
			}
		} else {
			if failN > 0 {
				rc.success() // the active endpoints handshaked — clear any transient burns
			}
			failN = 0
			b.send(typePing, nil, b.peer.Load())
			rc.proactive(b.rotatePeerUDP, b.rotateSourceUDP, time.Now()) // moving target on both sides
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

func (b *UDP) sendInit() {
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

func (b *UDP) send(typ byte, payload []byte, to *net.UDPAddr) {
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

var errBadFrame = errors.New("core: bad frame")
