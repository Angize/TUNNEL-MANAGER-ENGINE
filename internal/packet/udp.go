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

// stagedBox is one server-side staged (pending) session: its sealer plus its own replay guard,
// adopted verbatim on promotion. A BOUNDED SET of these (maxStaged) replaces a single pending slot
// so a replayed init can no longer evict a legit client's staged session by overwriting one slot —
// promotion is still gated on a frame that actually opens under a candidate (which a replay can't
// produce), and an attacker now needs maxStaged DISTINCT captured inits to push a legit candidate
// out (was one). Shared by the datagram carriers (udp/raw/flux); touched only on the single receive
// goroutine, so it needs no lock.
type stagedBox struct {
	box *sealerBox
	rp  replayGuard
}

// maxStaged bounds the staged-candidate set (aligned with the handshake-cache size). Small: the set
// only ever holds one entry on the normal path, and every non-live frame trial-opens against each
// entry, so the bound also caps that per-packet work.
const maxStaged = 8

// stageSession appends a freshly derived session to the bounded staged set, evicting the OLDEST first
// (FIFO) when full so the just-staged (newest, legit) candidate always survives.
func stageSession(set []*stagedBox, s Sealer) []*stagedBox {
	if len(set) >= maxStaged {
		set = set[1:]
	}
	return append(set, &stagedBox{box: &sealerBox{s: s}})
}

// UDP carries L3 packets between a TUN device and a UDP peer.
type UDP struct {
	// conn is the live socket. It is an atomic pointer (not a plain *net.UDPConn) because a source-IP
	// rotation rebinds it: rotateSourceUDP opens a fresh socket on the new source IP, swaps it in, and
	// closes the old one. rebindGen is bumped on every deliberate rebind so the receive loop can tell a
	// rotation-induced ReadFromUDP error (reload the new conn and keep going) from a real socket death.
	conn      atomic.Pointer[net.UDPConn]
	rebindGen atomic.Int64
	rebindMu  sync.Mutex // serializes rebindSourceTo so a proactive rotation and a pin-poll adopt can't race the swap (double-close / socket leak)
	// Server-side listen sockets. A pooled server binds ONE socket per selected pool IP (not 0.0.0.0), so
	// only those IPs listen and the reply leaves from the SAME IP the client dialed (source-correct for a
	// NAT'd client). replyConn is the socket an AUTHENTICATED frame was last received on; tunToNet/writeCtrl
	// reply on it. It is committed only where the peer address is learned (post-auth), so a stray or hostile
	// datagram to another pool IP cannot hijack the reply source. rxConn stashes the current read loop's
	// socket as a candidate (under rxMu) until that authenticated commit. rxMu serializes the N read loops
	// into the single-receiver contract the crypto/replay/FEC path assumes.
	srvConns      []*net.UDPConn
	replyConn     atomic.Pointer[net.UDPConn]
	rxConn        atomic.Pointer[net.UDPConn]
	rxMu          sync.Mutex
	dev           *tun.Device
	keepalive     time.Duration
	deadAfterSecs int // per-tunnel self-heal deadline override (0 = default 3×keepalive/10s floor)
	obfs          bool
	cryptoOn      bool
	psk           string
	cipher        string
	isClient      bool

	peer    atomic.Pointer[net.UDPAddr]      // current known peer (server learns it)
	session atomic.Pointer[sealerBox]        // negotiated session sealer (nil until handshake / clear mode)
	rp      replayGuard                      // driven only by the single receive goroutine (netToTun on the client; serverReadLoop under rxMu on the server)
	staged  []*stagedBox                     // server: bounded set of sessions staged by recent inits, each promoted only once a frame opens under it
	hsCache initCache                        // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci      atomic.Pointer[crypto.Ephemeral] // client's current handshake ephemeral
	lastRx  atomic.Int64                     // unix-nano of the last authenticated frame (client staleness)
	hbRx    atomic.Int64                     // unix-nano of the last REAL inbound frame — feeds the status heartbeat; 0 until the peer answers (v2.48.7)
	// peerAnswered gates the clear-mode heal: it is set when the CURRENT peer replies and cleared on
	// every peer rotation, so success() only clears a burn on an endpoint that has actually replied
	// SINCE we (re)pointed at it — never a false heal on a just-jumped-to (unproven) endpoint.
	peerAnswered atomic.Bool

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

// pinFailRelease is how many proven-dead rounds (each already peerFailThreshold retransmits, or a full
// clear-mode staleness window, of no session) a manual pin absorbs before it auto-releases so the tunnel
// recovers instead of freezing on a blocked endpoint for the rest of pinTTL. The direct/datagram analogue
// of the ws pool's releasePinLocked. Two rounds keeps a real transient (which heals before even one round)
// from ever releasing a good pin, while still recovering well inside a manual pick's useful window.
const pinFailRelease = 2

// rotatePeerUDP points the client at the next pool endpoint: burn+advance (proactive=false) or a
// timed rotate (proactive=true). It resolves the endpoint and swaps b.peer, then clears the session
// so the next loop re-handshakes against the new destination. No-op when the pool did not move.
func (b *UDP) rotatePeerUDP(proactive bool) {
	if b.pp == nil {
		return
	}
	addr, moved := b.pp.nextEndpoint(proactive)
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
	// Give the jumped-to endpoint a FRESH staleness window and mark it unproven. This matters most for
	// a PROACTIVE rotation onto an untested (assumed-healthy) endpoint that turns out to be dead: without
	// the reset, lastRx stays recent from the old endpoint so clear-mode failover never fires and the
	// tunnel strands on the blackhole. Resetting makes sessionStale measure THIS endpoint, so a dead
	// proactive jump fails over within the dead window rather than stranding.
	b.lastRx.Store(time.Now().UnixNano())
	b.peerAnswered.Store(false)
	log.Printf("core/udp: rotated destination to %s", addr)
	// BUG #30: refresh the live-carrier descriptor so the status file's "active" field tracks the NEW
	// destination instead of staying frozen at the initial peer. Same format SetStatusPath uses
	// ("udp · "+peer, peer=UDPAddr.String()). Only the DESTINATION path refreshes active; the source
	// path (rotateSourceUDP) leaves it, since "active" names the destination, not the source.
	b.st.setActive("udp · " + ua.String())
	b.st.down("peer-rotate", "ip:"+addr) // clears the session -> re-handshake -> reconnect pairs the down
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
	addr, moved := b.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	if host, ok := b.rebindSourceTo(addr); ok {
		log.Printf("core/udp: rotated source to %s", host)
		// A source rebind keeps the SAME AEAD session alive (no re-handshake), so there is no matching
		// reconnect. Use event() not down(): log the rotation but do NOT arm wasDown (which would leave a
		// phantom pending recovery that a later unrelated re-handshake would mis-pair). Carry the new IP.
		b.st.event("down", "src-rotate", "ip:"+host)
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
	// "Make this active" is a deliberate operator jump — logged SILENTLY like the ws edge pool: only the
	// active endpoint changes, no down/up in the event ring. The session clear above still forces the
	// re-handshake onto the pinned peer; setActive keeps "active" tracking it (see rotatePeerUDP). We do NOT
	// emit down("peer-pin") — that armed a paired reconnect and surfaced a manual jump as a rotation event.
	b.st.setActive("udp · " + ua.String())
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
		// Silent, like the ws edge pool: a manual source "make this active" changes only the active source
		// (the source pool's own status file reflects it). The session survives, so there's nothing to
		// reconnect and no event is emitted — we no longer log a src-pin here.
	}
}

// ProbeAllNow retests every suspect/dead endpoint on both pools at once (the panel "probe now" control,
// delivered as SIGHUP). No-op unless pooled.
// probeAllPools pulls every suspect/dead endpoint's retest forward on both of a carrier's pools (the
// "probe now" control). Shared by udp/raw/flux, which differ only by which struct fields hold the pools.
func probeAllPools(pp, sp *PeerPool) {
	if pp != nil {
		pp.probeAllNow()
	}
	if sp != nil {
		sp.probeAllNow()
	}
}

// runPinPoll is the 1s ticker that applies operator pins for a datagram carrier: identical across
// udp/raw/flux, which inject their own close channel and adopt-peer/adopt-source callbacks.
func runPinPoll(rc *rotationController, closeCh <-chan struct{}, adoptPeer, adoptSource func()) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-closeCh:
			return
		case <-t.C:
			rc.pollPins(adoptPeer, adoptSource)
		}
	}
}

func (b *UDP) ProbeAllNow() {
	probeAllPools(b.pp, b.sp)
}

// pinPollLoop polls the pools' cmd files on a 1s ticker and applies any operator pin. Runs until Close.
func (b *UDP) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, b.closeCh, b.adoptPeerUDP, b.adoptSourceUDP)
}

// SetDeadAfter (client) tightens the session-stale deadline to the per-tunnel dead_after_secs so the
// tunnel re-handshakes faster than the default (3×keepalive). No-op for secs<=0. Call before Run.
func (b *UDP) SetDeadAfter(secs int) {
	if secs > 0 {
		b.deadAfterSecs = secs
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
func (b *UDP) deadWin() time.Duration { return sessionStaleWindow(b.keepalive, b.deadAfterSecs) }
func (b *UDP) sessionStale() bool     { return staleSince(b.lastRx.Load(), b.deadWin()) }

// markRx stamps a genuine inbound frame: it advances BOTH the failover clock (lastRx) and the liveness
// heartbeat (hbRx) to the same instant. hbRx is set ONLY here — on proven inbound — so hb reads 0 until
// the peer actually answers, which is what keeps a still-connecting tunnel yellow instead of a false
// green. Seeds that only re-baseline the failover clock (initial connect, destination/source rotation)
// call lastRx.Store directly and must NOT call this, or a never-answered link would look alive.
func (b *UDP) markRx() {
	now := time.Now().UnixNano()
	b.lastRx.Store(now)
	b.hbRx.Store(now)
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

// Listen (server role) binds one socket per listen address and waits to learn the peer. A non-pooled
// server passes a single address; a pooled server passes one "ip:port" per selected pool IP, so only
// those IPs listen (not 0.0.0.0) and each reply leaves from the IP the client actually dialed.
func Listen(listenAddrs []string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int) (*UDP, error) {
	b := &UDP{dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, closeCh: make(chan struct{})}
	for _, listenAddr := range listenAddrs {
		la, err := net.ResolveUDPAddr("udp", listenAddr)
		if err == nil {
			var conn *net.UDPConn
			conn, err = net.ListenUDP("udp", la)
			if err == nil {
				b.srvConns = append(b.srvConns, conn)
				continue
			}
		}
		for _, c := range b.srvConns { // a later bind failed — release the ones already bound
			_ = c.Close()
		}
		return nil, err
	}
	if len(b.srvConns) == 0 {
		return nil, errors.New("udp listen: no listen address")
	}
	b.replyConn.Store(b.srvConns[0]) // default reply socket until the client is first heard
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

// serverReadLoop reads one server listen socket. All listen sockets funnel through rxMu into the single
// receiver contract the crypto/replay/handshake-cache/FEC path assumes; a point-to-point tunnel only
// receives on one server IP at a time, so it is effectively uncontended. The socket is stashed as the
// reply CANDIDATE (rxConn); it is promoted to the actual reply socket only when a frame AUTHENTICATES and
// the peer is (re)learned — so an unauthenticated datagram to another pool IP can't hijack the reply source.
func (b *UDP) serverReadLoop(c *net.UDPConn) error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		b.rxMu.Lock()
		b.rxConn.Store(c) // candidate; learnPeer promotes it to replyConn after the frame authenticates
		if b.fecDec != nil {
			b.rxAddr.Store(addr)
			b.fecDec.input(buf[:n])
		} else {
			b.deliver(buf[:n], addr)
		}
		b.rxMu.Unlock()
	}
}

// learnPeer records the authenticated client's source address and, on a server, promotes the socket the
// frame arrived on (rxConn) to the reply socket, so a pooled server replies from the exact IP the client
// dialed. Called ONLY after a frame authenticates (crypto) or in clear mode — never for an unauthenticated
// datagram — so a stray/hostile packet to another pool IP can't move the reply source. On the client the
// reply socket is the single dial socket, so replyConn is left untouched.
func (b *UDP) learnPeer(addr *net.UDPAddr) {
	// Commit the reply socket BEFORE publishing the peer: tunToNet gates its downstream send on
	// peer!=nil and then reads replyConn, so ordering the (sequentially-consistent) atomic stores this
	// way guarantees a sender that sees the new peer also sees the matching reply socket — never a stale
	// srvConns[0] for one packet on the very first authenticated frame.
	if !b.isClient {
		if c := b.rxConn.Load(); c != nil {
			b.replyConn.Store(c)
		}
	}
	b.peer.Store(addr)
}

// sendConn is the socket for an UNSOLICITED send (downstream data from tunToNet, FEC flush): the client's
// single socket, or (server) replyConn — the socket an authenticated frame was last received on, so a
// pooled server's downstream leaves from the exact IP the client dialed.
func (b *UDP) sendConn() *net.UDPConn {
	if b.isClient {
		return b.conn.Load()
	}
	return b.replyConn.Load()
}

// replySock is the socket for a SOLICITED reply (a handshake response or a pong, sent while processing an
// inbound packet under rxMu): the client's single socket, or (server) rxConn — the socket THIS inbound
// packet arrived on. Using rxConn (not replyConn) means a handshake response egresses from the exact IP
// the client dialed even before any data frame has authenticated, while a hostile/replayed init only ever
// echoes back on its own socket and never perturbs the persistent replyConn (which moves only on auth).
func (b *UDP) replySock() *net.UDPConn {
	if b.isClient {
		return b.conn.Load()
	}
	if c := b.rxConn.Load(); c != nil {
		return c
	}
	return b.replyConn.Load()
}

// initFec wires the FEC encoder/decoder (no-op when fec is off). Data shards emit to
// the current peer; recovered frames re-enter the normal receive path with the source
// of the packet that completed their block.
func (b *UDP) initFec(fec bool, fecData, fecParity int) {
	b.fecEnc, b.fecDec = newFecPair(fec, fecData, fecParity, "udp",
		func(pkt []byte) {
			if p := b.peer.Load(); p != nil {
				if c := b.sendConn(); c != nil {
					_, _ = c.WriteToUDP(pkt, p)
				}
			}
		},
		func(frame []byte) { b.deliver(frame, b.rxAddr.Load()) })
}

// Run blocks until one of the loops fails (e.g. a socket or the device closes). The client reads its one
// socket; a server reads each of its listen sockets (one per pool IP) in its own loop.
func (b *UDP) Run() error {
	errc := make(chan error, 2+len(b.srvConns))
	go func() { errc <- b.tunToNet() }()
	if b.isClient {
		go func() { errc <- b.netToTun() }()
		go b.clientLoop()
		b.st.setDW(int64(b.deadWin().Seconds())) // publish the resolved dead-window so the reader ages hb against it
		go heartbeat(b.st, &b.hbRx, b.closeCh)   // publish lastRx to the status file so an idle tunnel reads live, not half-open
	} else {
		for _, c := range b.srvConns {
			c := c
			go func() { errc <- b.serverReadLoop(c) }()
		}
	}
	return <-errc
}

// Close tears down the socket(s) (which unblocks the loops) and stops the client loop. Safe to call more
// than once.
func (b *UDP) Close() error {
	b.closeOnce.Do(func() { close(b.closeCh) })
	if b.fecEnc != nil {
		b.fecEnc.Close() // stop the FEC flush timer before the socket goes away
	}
	if b.isClient {
		if c := b.conn.Load(); c != nil {
			return c.Close()
		}
		return nil
	}
	var err error
	for _, c := range b.srvConns {
		if e := c.Close(); e != nil {
			err = e
		}
	}
	return err
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
	return sealBody(b.sealer(), b.obfs, typ, payload, padMaxFor(typ))
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
		if c := b.sendConn(); c != nil {
			if _, err := c.WriteToUDP(frame, peer); err != nil {
				log.Printf("core: write error: %v", err)
			}
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
	b.markRx()                 // the peer is answering (clear mode has no session to prove it)
	b.peerAnswered.Store(true) // this endpoint has now replied since we pointed at it -> safe to heal its burn
	if b.pp == nil {           // a pooled client owns its peer (mirror the crypto path); a server always learns it
		b.learnPeer(addr)
	}
	b.dispatch(pkt[1], iff(pkt[1] == typeData, pkt[2:], nil), addr)
}

// openWith tries to open one datagram under a specific session sealer, returning the
// authenticated frame. It touches no session/replay state, so a frame can safely be tried
// against both the live and a pending session.
// openFrame is the shared receive-side frame opener for the datagram carriers (udp/raw/flux): obfs
// path when obfs is on, else parse the magic/type header and authenticate the type byte via the
// sealer. The three carriers' openWith methods differ only by the obfs field, so they delegate here.
// sealBody builds one outbound frame for typ/payload: obfs, crypto (magic+type+sealed), or clear
// (magic+type+payload). The send-side mirror of openFrame; shared by udp/raw/flux, which each pass their
// own padMax (padMaxFor for udp/raw, fluxPadMax for flux — both pure reads, so evaluating eagerly at the
// call site is harmless even when obfs is off and padMax goes unused).
func sealBody(s Sealer, obfs bool, typ byte, payload []byte, padMax int) ([]byte, error) {
	if obfs {
		return obfsSeal(s, typ, payload, padMax)
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

func openFrame(s Sealer, data []byte, obfs bool) (typ byte, session, seq uint64, payload []byte, oerr error) {
	if obfs {
		return obfsOpen(s, data)
	}
	if len(data) >= 2 && data[0] == magic {
		typ = data[1]
		session, seq, payload, oerr = s.Open(data[2:], []byte{typ})
		return
	}
	return 0, 0, 0, nil, errBadFrame
}

func (b *UDP) openWith(s Sealer, pkt []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, pkt, b.obfs)
}

// handleCrypto is the crypto-on receive path: try the frame as data under the current
// session; failing that, under a pending session staged by a recent init (promoting it if
// it opens); failing that, as a handshake message.
func (b *UDP) handleCrypto(pkt []byte, addr *net.UDPAddr) {
	if s := b.sealer(); s != nil {
		if typ, session, seq, payload, oerr := b.openWith(s, pkt); oerr == nil && b.rp.ok(session, seq) {
			// authenticated, fresh frame -> now safe to (re)learn the peer address
			b.markRx() // the session is answering
			// The DESTINATION pool owns the client's peer: don't rebind it from a reply's source, so a
			// client's own rotation isn't silently pulled off the endpoint its pool is driving. Servers
			// (pp==nil) learn the client here — which lets them follow a client's SOURCE rotation and, on
			// a pooled server, promote this socket as the reply source (the IP the client actually dialed).
			if b.pp == nil {
				b.learnPeer(addr)
			}
			b.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a session STAGED by a recent
	// init. Only a frame that actually opens under a candidate promotes it (and rebinds the peer), so
	// a replayed init — which stages a session an attacker cannot produce a frame for — never tears
	// down the live session or resets its replay window. The live session was tried first above, so an
	// established tunnel never reaches this loop; on the normal path the set holds one candidate.
	for _, st := range b.staged {
		if typ, session, seq, payload, oerr := b.openWith(st.box.s, pkt); oerr == nil && st.rp.ok(session, seq) {
			b.session.Store(st.box)
			b.rp = st.rp
			b.staged = nil
			b.markRx() // a pending session promoted -> genuine inbound
			b.learnPeer(addr)
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
		// Clear the ephemeral so a replayed resp captured on-path hits the ci==nil guard above
		// instead of re-parsing and wiping the fresh anti-replay window. A legitimate
		// re-handshake regenerates a fresh ci in sendInit (ci==nil path).
		b.ci.Store(nil)
		b.markRx()              // server RESP arrived: genuine inbound (green on a real connect)
		b.st.reconnected("udp") // recovery after a self-heal (nil-safe; silent on first connect)
		return
	}
	// server: authenticate an init, reply, and install the fresh session.
	// Compute-DoS mitigation: an attacker replaying captured valid inits at high rate
	// would otherwise force a fresh ECDH+HKDF (GenerateEphemeral+SessionSealer) per packet.
	// If this init matches one we recently answered (while a pending session is current),
	// just re-send the response we already computed and return before that expensive
	// crypto. The handshake outcome is unchanged (staged/promote-on-open is untouched); a
	// genuinely new init falls through to the full handshake below. The cache is a small
	// LRU (not a single entry) so alternating two captured inits cannot bust it. It is
	// touched only on this single receive goroutine (like staged), so no locking is needed.
	if len(b.staged) > 0 {
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
	b.staged = stageSession(b.staged, s)
	if msg2 := crypto.RespMsg(b.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while a staged session
		// is still current) is served without recomputing the crypto above. put copies pkt
		// (it aliases the receive buffer); msg2 is a fresh slice, safe to keep.
		b.hsCache.put(pkt, msg2)
		b.writeCtrl(msg2, addr)
	}
}

// writeCtrl sends a control/handshake datagram, tagging it passthrough under FEC so
// the peer's decoder forwards it straight through (never held in a block or parsed as
// a shard). to may differ from the learned peer (a server's handshake reply). It goes out
// replySock — on a server, the socket THIS inbound packet arrived on — so a handshake reply
// or pong egresses from the exact IP the client dialed (writeCtrl is only ever called while
// processing that inbound packet, under rxMu, so rxConn is the right socket).
func (b *UDP) writeCtrl(pkt []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	if c := b.replySock(); c != nil {
		_, _ = c.WriteToUDP(fecTag(b.fecEnc, pkt), to)
	}
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
	// Seed the staleness baseline NOW (clear mode). Without a baseline, sessionStale() returns false
	// while lastRx==0, so a clear-mode failover-only pool whose FIRST endpoint is dead from the start
	// never fires — it never receives a reply, so lastRx stays 0 and the tunnel strands on the blackhole.
	// Starting the clock at connect makes a from-start-dead endpoint fail over after the dead window.
	b.lastRx.Store(time.Now().UnixNano())
	for {
		if b.cryptoOn && b.sealer() != nil && b.sessionStale() {
			b.session.Store(nil) // server likely restarted — drop the dead session so we re-handshake
			b.ci.Store(nil)
			log.Print("core: no reply from the peer's session — re-handshaking (peer likely restarted)")
			b.st.down("stale", "udp") // precise reason for the panel log (nil-safe when off)
		}
		// Clear mode (no crypto) has no handshake whose failure would drive failover, so a dead pool
		// endpoint would otherwise strand the tunnel forever. Use receive-staleness instead: the peer
		// pongs our keepalive pings, so once it stops answering (lastRx ages past the dead window) burn
		// and advance the pool. The baseline is seeded at connect and reset on every rotation, so a
		// fresh tunnel or a just-jumped-to endpoint gets a full window before it can false-fail.
		if !b.cryptoOn && rc.active() && b.sessionStale() {
			rc.fail(b.rotatePeerUDP, b.rotateSourceUDP)
			b.lastRx.Store(time.Now().UnixNano()) // fresh window even if the pool couldn't move (single endpoint / source-only rotate)
			b.peerAnswered.Store(false)           // stale -> the current endpoint is no longer proven answering
			b.st.down("stale", "udp")
		}
		if b.sealer() == nil && b.cryptoOn {
			b.sendInit()
			if failN++; rc.active() && failN >= peerFailThreshold {
				rc.fail(b.rotatePeerUDP, b.rotateSourceUDP) // burn+advance dest; walk source once dests cycle
				failN = 0
			}
		} else {
			// Clear any transient burn on the endpoints that are proving themselves. Crypto signals this
			// via a completed handshake (failN>0 then a session); clear mode has no handshake, so use the
			// data plane: peerAnswered is set when the CURRENT endpoint replies and cleared on rotation,
			// so healing here can never falsely clear a just-jumped-to (unproven) endpoint's burn.
			heal := failN > 0 || (!b.cryptoOn && rc.active() && b.peerAnswered.Load())
			if heal {
				healEvents(b.st, rc) // active endpoints alive — clear transient burns (and release a landed pin), emit any heal
			}
			// BUG #35: clear mode has no handshake to fire st.reconnected(), so a self-heal down() (the
			// clear-mode failover above, or a peer rotate/pin) would arm wasDown with no matching "up".
			// Pair it on the data-plane recovery: once the CURRENT endpoint answers again (peerAnswered,
			// set by deliver and cleared on every rotation), report the reconnect. reconnected() is a
			// no-op unless a down is pending, so calling it on each answering loop never invents an "up".
			if !b.cryptoOn && rc.active() && b.peerAnswered.Load() {
				b.st.reconnected("udp")
			}
			failN = 0
			b.send(typePing, nil, b.peer.Load())
			rc.proactive(b.rotatePeerUDP, b.rotateSourceUDP, time.Now()) // moving target on both sides
			if b.cryptoOn && b.sealer() == nil {
				// A proactive DESTINATION rotation just cleared the crypto session — loop back NOW to send
				// the re-handshake init immediately, instead of first sleeping the 1s retransmit interval
				// below, so the rotation gap is ~1 RTT rather than ~1s (matters for live streams). Clear
				// mode has no session/handshake so this never fires there; a duplicated init is harmless.
				continue
			}
		}
		var wait time.Duration
		if b.sealer() == nil && b.cryptoOn {
			wait = time.Second // retransmit the handshake faster than keepalive
		} else {
			wait = keepaliveInterval(b.keepalive, b.psk)
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
