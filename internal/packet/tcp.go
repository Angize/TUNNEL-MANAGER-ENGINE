// This file implements the core carrier over TCP. It mirrors udp.go (same
// type frame and Sealer contract) but adapts to a byte stream.
//
// Legacy framing (obfs off) — length-prefixed so the reader can reframe:
//
//	[0:2] uint16 big-endian N = length of the frame that follows (magic+type+payload)
//	[2]   magic = 0xB1
//	[3]   type  = 0 data | 1 ping | 2 pong
//	[4:]  payload — when crypto is on this is sealed(nonce||ct) for EVERY type
//	      (ping/pong seal an empty payload) so control frames are authenticated;
//	      with crypto off it is the raw IP packet for data, empty for ping/pong
//
// Obfs framing (obfs on) — no constant bytes on the wire:
//
//	handshake: each side writes a 24-byte random salt, then reads the peer's.
//	per frame: [0:2] uint16 length XOR ChaCha20-keystream(PSK,salt)
//	           [2:]  AEAD-sealed [type][realLen][payload][random-pad]
//
// Roles: the "server" listens and accepts; the "client" dials and reconnects
// automatically with a short backoff. Because a core tunnel is a single
// point-to-point link, only one connection is active at a time — a new accepted
// connection replaces (and closes) the previous one. A single TUN reader feeds
// whichever connection is currently live via an atomic pointer, so no L3 packet
// is bound to a connection that may have dropped.
package packet

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tlscover"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	maxFrame = 65535 // uint16 length prefix ceiling (payload fits far under this)

	// readBufSize is the bufio read buffer allocated per connection. It is kept
	// small (not maxFrame+2) so an unauthenticated peer cannot force a ~64 KB
	// eager allocation just by connecting; bufio reads larger frames directly
	// into the destination, so this does not cap frame size.
	readBufSize = 4096

	// handshakeTimeout bounds how long an UNAUTHENTICATED peer may hold a server
	// goroutine before its first frame authenticates — far shorter than the
	// established-connection idle deadline, to blunt slowloris/half-open floods.
	handshakeTimeout = 10 * time.Second

	// writeTimeout caps a single frame write so a peer advertising a zero receive
	// window cannot block the sole TUN reader (tunLoop) indefinitely.
	writeTimeout = 30 * time.Second

	// maxPreAuthConns bounds concurrent not-yet-authenticated server handlers, so
	// a connection flood cannot exhaust goroutines/fds/memory before auth.
	maxPreAuthConns = 128

	// pingLossThreshold closes a CLIENT connection after this many consecutive keepalive
	// pings go unanswered (no inbound frame of ANY type in between). It is a faster liveness
	// signal than the b.idle read deadline for a silently black-holed carrier: at ~3×keepalive
	// it trips well before idle (≥60s), so dialLoop re-dials sooner. b.idle stays as a backstop.
	pingLossThreshold = 3

	// probeTimeout bounds a single differential/retest edge probe (TCP dial + TLS, no WS, no data).
	probeTimeout = 5 * time.Second

	// minLiveness (pool client) is the shortest a carrier may live and still count as a healthy
	// session. A connection that handshakes then dies sooner than this is treated as a data-plane
	// fault (throttle / blackhole-after-handshake) against its edge, not a healthy session.
	minLiveness = 20 * time.Second

	// maxAuthConns bounds concurrent AUTHENTICATED server connections. A warm-standby client
	// keeps a second live carrier up (make-before-break), so the server must NOT evict the
	// previous connection when a new one authenticates; instead it holds up to this many and,
	// when over the cap, reaps the oldest idle one (the per-connection idle read-deadline reaps
	// a truly dead conn anyway). 3 leaves headroom for the brief active+standby+handoff overlap.
	maxAuthConns = 3
)

var (
	errDesync      = errors.New("core/tcp: stream desync")
	errPingTimeout = errors.New("core/tcp: keepalive pings unanswered")
)

// connFramer wraps a stream connection and owns the seal<->frame transform in
// both directions. A write lock lets the TUN reader and the keepalive loop emit
// frames without interleaving bytes (and, in obfs mode, without racing the
// stateful length keystream).
type connFramer struct {
	conn   net.Conn
	r      *bufio.Reader
	mu     sync.Mutex
	sealer Sealer
	obfs   bool
	psk    string

	// obfs length-prefix keystreams (nil until established). writeKS is keyed by
	// the salt we sent, readKS by the salt the peer sent (read lazily on the
	// first frame). saltSent guards the one-time salt emission.
	writeKS  *chacha20.Cipher
	readKS   *chacha20.Cipher
	saltSent bool

	// rp is this connection's inbound anti-replay window. It is PER-CONNECTION (not
	// shared across connections) so two briefly-overlapping connections during a
	// client reconnect cannot flip-flop a shared window's session id and let a
	// captured frame from either session slip through. A single connection only ever
	// carries one peer session and is read by exactly one goroutine (the handler that
	// authenticates its first frame and then runs serve), so the lock-free
	// replayGuard is safe here.
	rp replayGuard

	// unanswered counts CLIENT keepalive pings sent with no inbound frame in between.
	// keepaliveLoop bumps it per ping and drops the connection once it hits
	// pingLossThreshold; serve() resets it to 0 on any received frame. Touched by the
	// keepalive goroutine and the read goroutine, so it is atomic.
	unanswered atomic.Int32
}

// sendSalt emits our per-connection salt once and arms the write keystream.
// The server calls it only AFTER it has authenticated the client's first frame,
// so a peer that does not know the PSK gets zero bytes back (probe resistance).
func (cf *connFramer) sendSalt() error {
	if cf.saltSent {
		return nil
	}
	salt := make([]byte, obfsSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	ws, err := newObfsStream(cf.psk, salt)
	if err != nil {
		return err
	}
	cf.mu.Lock()
	cf.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, werr := cf.conn.Write(salt)
	if werr == nil {
		cf.writeKS = ws
		cf.saltSent = true
	}
	cf.mu.Unlock()
	return werr
}

// ensureReadKS reads the peer's salt (once) and arms the read keystream.
func (cf *connFramer) ensureReadKS() error {
	if cf.readKS != nil {
		return nil
	}
	peer := make([]byte, obfsSaltLen)
	if _, err := io.ReadFull(cf.r, peer); err != nil {
		return err
	}
	rs, err := newObfsStream(cf.psk, peer)
	if err != nil {
		return err
	}
	cf.readKS = rs
	return nil
}

// writeFrame seals payload and writes one framed message.
func (cf *connFramer) writeFrame(typ byte, payload []byte) error {
	if cf.obfs {
		sealed, err := obfsSeal(cf.sealer, typ, payload, padMaxFor(typ))
		if err != nil {
			return err
		}
		if len(sealed) > maxFrame {
			return io.ErrShortWrite
		}
		out := make([]byte, 2+len(sealed))
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(sealed)))
		copy(out[2:], sealed)
		cf.mu.Lock()
		cf.writeKS.XORKeyStream(out[0:2], lb[:]) // mask length; advances keystream
		cf.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err = cf.conn.Write(out)
		cf.mu.Unlock()
		return err
	}

	// Legacy: [len][magic][type][sealed]. With crypto on we seal EVERY type
	// (ping/pong seal an empty payload) so control frames are authenticated.
	sealed := payload
	if cf.sealer != nil {
		s, err := cf.sealer.Seal(payload, []byte{typ}) // authenticate the type byte
		if err != nil {
			return err
		}
		sealed = s
	}
	n := 2 + len(sealed)
	if n > maxFrame {
		return io.ErrShortWrite
	}
	out := make([]byte, 2+n)
	binary.BigEndian.PutUint16(out[0:2], uint16(n))
	out[2] = magic
	out[3] = typ
	copy(out[4:], sealed)
	cf.mu.Lock()
	cf.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := cf.conn.Write(out)
	cf.mu.Unlock()
	return err
}

// readFrame reads one framed message and returns its type, the sender's
// (session, seq) for anti-replay, and the real payload (padding stripped, data
// unsealed). ping/pong carry a nil/empty payload. session/seq are 0 in clear
// mode (no crypto), where replay cannot be detected.
func (cf *connFramer) readFrame() (typ byte, session uint64, seq uint64, payload []byte, err error) {
	if cf.obfs {
		if err := cf.ensureReadKS(); err != nil { // peer salt precedes its frames
			return 0, 0, 0, nil, err
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(cf.r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	if cf.obfs {
		var lb [2]byte
		cf.readKS.XORKeyStream(lb[:], hdr[:]) // unmask length; advances keystream
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 1 || n > maxFrame {
			return 0, 0, 0, nil, errDesync
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(cf.r, buf); err != nil {
			return 0, 0, 0, nil, err
		}
		return obfsOpen(cf.sealer, buf)
	}

	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 2 {
		return 0, 0, 0, nil, errDesync
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(cf.r, buf); err != nil {
		return 0, 0, 0, nil, err
	}
	if buf[0] != magic {
		return 0, 0, 0, nil, errDesync
	}
	typ = buf[1]
	if cf.sealer != nil { // crypto on: every type is sealed and authenticated
		session, seq, payload, err = cf.sealer.Open(buf[2:n], []byte{typ}) // type-flip -> open fails
		if err != nil {
			return 0, 0, 0, nil, err
		}
		return typ, session, seq, payload, nil
	}
	if typ == typeData { // clear mode: only data carries a payload
		return typ, 0, 0, buf[2:n], nil
	}
	return typ, 0, 0, nil, nil
}

// TCP carries L3 packets between a TUN device and a TCP peer.
type TCP struct {
	dev       *tun.Device
	cryptoOn  bool
	cipher    string
	keepalive time.Duration
	obfs      bool
	psk       string
	idle      time.Duration // read deadline; reaps dead/probe connections

	cover    bool             // wrap the connection in a REALITY-style TLS cover
	coverSNI string           // client: SNI to present; server: real dest to borrow
	coverSrv *tlscover.Server // server-side REALITY responder (nil on the client)

	// WebSocket carrier (transport "ws"): the stream is wrapped in RFC 6455 binary
	// frames after an HTTP Upgrade, so it can be fronted through a CDN. ws is
	// mutually exclusive with cover. On the client, wsTLS wraps the connection in a
	// standard TLS session (ServerName=wsHost) BEFORE the upgrade, so the client
	// speaks wss:// to a CDN edge; the server stays plain (the CDN terminates TLS).
	ws     bool
	wsHost string // client: Host header + TLS SNI (the fronting/origin domain)
	wsPath string // client: request path (default "/")
	wsTLS  bool   // client: TLS to the edge before the WebSocket upgrade
	wsECH  []byte // client: ECHConfigList — when set, the SNI is encrypted (hidden)

	pool   *wsPool       // client: rotating edge pool (nil = single fixed edge above)
	rotate time.Duration // client: proactive pool-rotation interval (0 = failover-only)
	st     *coreStatus   // client + single-edge ws/xhttp: self-heal event ring -> status file (nil = off / pool / server)

	// pp is the DESTINATION rotation pool for the direct TCP carriers (plain tcp / tcp+cover): the
	// client cycles the peer IPs and burns a blocked one so a single filtered server IP doesn't kill
	// the tunnel. It is the direct-transport analogue of the ws edge pool (which owns rotation on the
	// ws path), so it is only ever set on a non-ws client. nil = single fixed peer (b.addr), no
	// rotation. Unlike the datagram carriers' atomic peer swap, TCP rotates by re-dialing: dialTarget
	// reads the pool's current endpoint and dialLoop burns/advances it on a dead/blocked dial.
	pp *PeerPool
	// sp is the SOURCE rotation pool: the local IP the client dials FROM. TCP applies it via the
	// dialer's LocalAddr, so a rotation is picked up on the next re-dial (sourceIP reads sp.current()).
	// nil = fixed bindIP. Direct-tcp client only.
	sp *PeerPool

	sniSplit bool   // client ws/xhttp: split the ClientHello so the cleartext SNI crosses a TCP segment boundary
	splitPos int    // explicit split offset into the ClientHello (0 = auto: middle of the hostname)
	sniMode  string // "split" (in-order) | "disorder" (low-TTL head, desyncs a reassembling DPI)
	splitTTL int    // disorder head-segment TTL (0 = default)

	// probeFn lets tests substitute a deterministic reachability oracle for probeEdge (which
	// does a real TCP+TLS dial). nil in production -> the differential prober uses probeEdge.
	probeFn func(ip string, sni wsSNIEntry) bool

	// manualSwitch marks the NEXT carrier drop as operator-initiated (a pin / manual rotate via
	// rotate1), so the dial loops (a) don't record it as a data-plane fault, and (b) in warm mode
	// re-dial the ACTIVE from current() (which honors the just-set edge) instead of promoting the
	// pre-built warm standby — which is on a different edge and would ignore the operator's choice.
	manualSwitch atomic.Bool

	// lastErr holds the most recent CAUSE of a client carrier death (as a string), so the pool can
	// record a precise "down" reason for the panel log instead of a guess. "use of closed network
	// connection" is a consequence (we closed it) and is deliberately never stored.
	lastErr atomic.Value // string

	// warmStandby (client + pool) keeps a SECOND, fully-handshaked carrier connection to another
	// pool edge warm in the background. On the active carrier's failure OR a proactive rotation
	// the standby is promoted instantly (an atomic b.cur swap) instead of dialing fresh, so the
	// TUN never waits on a cold dial. Only the client's warm loop uses standby/standbyConn; the
	// server-side change (no connect-time eviction + downstream-follows-data) is always on and
	// stays behaviorally identical for a single connection.
	warmStandby bool
	standby     atomic.Pointer[connFramer] // client+warm: the warm standby framer (nil when none)
	standbyConn atomic.Pointer[net.Conn]   // client+warm: the standby's live conn (for teardown)

	// xhttp carrier (transport "ws" with ws_xhttp): the core stream rides an HTTP request
	// pair (packet-up: GET-down + seq-POSTs-up) or a single full-duplex request
	// (stream-one) instead of a WebSocket upgrade, so it passes CDNs that block WebSocket.
	// Same fronting fields (wsHost/wsTLS/wsECH/wsPath) apply. Because the client carries
	// core frames directly over these requests (the HTTP layer replaces the WS upgrade),
	// the server must NOT run wsServerHandshake on an xhttp conn — see handleServerConn.
	xhttp      bool
	xhMode     string                      // client: "stream" (single full-duplex request) else packet-up
	xhTLS      *tls.Config                 // test-only: overrides the client edge TLS config (nil in production)
	httpSrv    atomic.Pointer[http.Server] // server: the xhttp endpoint (nil otherwise); atomic — written by runXHTTPServer's goroutine, read by Close
	xhMu       sync.Mutex
	xhSessions map[string]*xhttpSession

	isClient bool
	addr     string // server: listen addr; client: peer addr
	bindIP   string // client: source IP to dial FROM (empty = kernel default); tcp/ws/xhttp only

	// TCP-segment injection desync (client, optional): after each kernel TCP connect we inject a
	// few decoy TCP segments on the real 4-tuple (low-TTL, so they die before the edge/server) to
	// mis-sync a stateful DPI, leaving the kernel-owned connection untouched. Primitive fields
	// (not the linux-only desyncCfg) so this compiles on every platform; the linux sendTCPFakes
	// reads them. Best-effort: needs CAP_NET_RAW (AF_PACKET); a failure just skips the decoys.
	dsOn       bool
	dsTTL      int
	dsCount    int
	dsMode     string
	dsFailOnce sync.Once // logs an AF_PACKET/capability failure at most once (fired per connect)

	ln      net.Listener
	cur     atomic.Pointer[connFramer] // currently live connection / server downstream target (nil when none)
	curConn atomic.Pointer[net.Conn]   // client+pool: the live carrier conn, closed to force a re-dial on rotation
	closed  atomic.Bool
	closeCh chan struct{}
	preAuth chan struct{} // permits: caps concurrent unauthenticated handlers

	// authConns tracks the server's AUTHENTICATED connections (oldest first) so a warm-standby
	// client can hold a second live conn without the newest evicting the previous. Bounded by
	// maxAuthConns; over the cap the oldest non-downstream conn is reaped. Server-side only.
	authMu    sync.Mutex
	authConns []*connFramer
}

// SetSourceIP pins the client's outbound dials to a specific source IP (the node's own
// registered IP), so on a multi-IP host the peer/CDN sees that IP instead of the kernel's
// default primary. No effect on the server side or on raw/flux carriers. Call before Run.
func (b *TCP) SetSourceIP(ip string) { b.bindIP = ip }

// SetPeerPool (client, direct tcp/cover only) wires a destination rotation pool: the client dials the
// pool's current endpoint, burns one that won't connect (or dies immediately), and a proactive timer
// also rotates. The ws path has its own edge pool, so this is refused there. nil / single-endpoint =
// no rotation. main wires it via the shared SetPeerPool type assertion. Call before Run().
func (b *TCP) SetPeerPool(pp *PeerPool) {
	if b.isClient && !b.ws {
		b.pp = pp
	}
}

// dialTarget is the address the next dial should use: the rotation pool's current endpoint when a
// pool is wired, otherwise the fixed peer. b.addr is never mutated (the pool holds the moving state,
// like the ws pool), so this is safe to read from the dial goroutine while a timer rotates the pool.
func (b *TCP) dialTarget() string {
	if b.pp != nil {
		return b.pp.current()
	}
	return b.addr
}

// SetSourcePool (client, direct tcp/cover only) wires a source-IP rotation pool: the local IP the
// client dials FROM is cycled/burned alongside the destination. Refused on the ws path (its edge pool
// owns rotation). nil / single-endpoint = the fixed bindIP. Call before Run().
func (b *TCP) SetSourcePool(sp *PeerPool) {
	if b.isClient && !b.ws {
		b.sp = sp
	}
}

// sourceIP is the local IP the next dial binds to: the source pool's current entry when wired, else
// the fixed bindIP. Like dialTarget, b.bindIP is never mutated — the pool holds the moving state — so
// this is safe to read from the dial goroutine while a timer rotates the pool.
func (b *TCP) sourceIP() string {
	if b.sp != nil {
		return b.sp.current()
	}
	return b.bindIP
}

// rotateSourceTCP advances the source pool so the NEXT dial binds to a new local IP, returning whether
// it actually moved (the proactive timer uses that to decide whether to force a re-dial). It performs
// no teardown itself — the caller (a dead dial, or the proactive timer that closes the conn) drives
// the re-dial that picks up sourceIP(). No-op / false without a source pool.
func (b *TCP) rotateSourceTCP(proactive bool) bool {
	if b.sp == nil {
		return false
	}
	var addr string
	var moved bool
	if proactive {
		addr, moved = b.sp.rotateOnce()
	} else {
		addr, moved = b.sp.fail()
	}
	if moved {
		log.Printf("core/tcp: rotated source to %s", addr)
	}
	return moved
}

// SetDesync (client, optional) turns on TCP-segment injection desync for the tcp/cover/ws
// carriers: after each connect, sendTCPFakes injects `count` decoy segments on the real
// 4-tuple to mis-sync a stateful DPI. Stores the config; the actual injection is Linux-only
// (AF_PACKET). No-op on the server. Call before Run(). The same config surface (fake_*) the
// raw/flux carriers use — main wires it via the same SetDesync type assertion.
func (b *TCP) SetDesync(on bool, ttl, count int, mode string) {
	if !b.isClient || !on {
		return
	}
	b.dsOn, b.dsTTL, b.dsCount, b.dsMode = true, ttl, count, mode
}

// SetSNISplit (client, ws/xhttp) turns on SNI fragmentation: the TLS ClientHello to the edge is
// written across two TCP segments so the cleartext SNI is split, defeating a stateless SNI-blocklist
// DPI. pos is the split offset into the ClientHello (0 = auto: the middle of the hostname). Only
// meaningful with wss; a no-op on the server or a non-ws carrier. main wires it via the shared
// SetSNISplit type assertion. Call before Run().
func (b *TCP) SetSNISplit(on bool, pos int, mode string, ttl int) {
	if !b.isClient || !on || !b.ws {
		return
	}
	b.sniSplit, b.splitPos, b.sniMode, b.splitTTL = true, pos, mode, ttl
}

// fragWrap wraps conn in a ClientHello-splitting fragConn when SNI fragmentation is enabled, else
// returns conn unchanged. host is the SNI, used for auto split-point location.
func (b *TCP) fragWrap(conn net.Conn, host string) net.Conn {
	if b.sniSplit {
		return newFragConn(conn, host, b.splitPos, b.sniMode, b.splitTTL)
	}
	return conn
}

// SetStatusPath (client, single-edge ws/xhttp) wires a status-file event ring so the carrier's
// precise self-heal events (e.g. an in-band ECH self-heal) reach the node/panel system log — the
// same file shape the datagram carriers write. A pool writes its own richer status file, so this is
// skipped when a pool is configured; the server never wires it. main wires it via the shared
// SetStatusPath type assertion. Call before Run().
func (b *TCP) SetStatusPath(path string) {
	if !b.isClient || path == "" || b.pool != nil {
		return
	}
	carrier := "ws"
	if b.xhttp {
		carrier = "xhttp"
	}
	b.st = newCoreStatus(path, carrier+" · "+b.addr)
}

// dialer returns a net.Dialer that, when a source IP is pinned, binds the outbound socket to
// it (LocalAddr). A malformed or non-local IP is ignored (falls back to the kernel default).
func (b *TCP) dialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if src := b.sourceIP(); src != "" { // rotation pool's current source, or the fixed bindIP
		if ip := net.ParseIP(src); ip != nil {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	return d
}

func idleFor(keepalive time.Duration) time.Duration {
	d := 4 * keepalive
	if d < 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

// DialTCP (client role) targets peerAddr and reconnects on drop. When cover is
// set the connection is wrapped in a Chrome-fingerprinted TLS session presenting
// coverSNI, so it looks like HTTPS on the wire.
func DialTCP(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, cover bool, coverSNI string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		cover: cover, coverSNI: coverSNI,
		idle: idleFor(keepalive), isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// DialWS (client role) is DialTCP over a WebSocket carrier: it dials peerAddr (a
// CDN edge or the origin), optionally wraps it in TLS (wsTLS, ServerName=wsHost),
// then performs the WebSocket upgrade with Host=wsHost before the core framing runs.
func DialWS(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher, wsHost, wsPath string, wsTLS bool, wsECH []byte) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, wsHost: wsHost, wsPath: wsPath, wsTLS: wsTLS, wsECH: wsECH,
		idle: idleFor(keepalive), isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// DialWSPool is DialWS over a rotating edge POOL: the client cycles (edge-IP × SNI)
// combinations from the pool (each SNI with its own ECH), moving before any single
// edge is fingerprinted and burning a blocked one. rotate is the proactive rotation
// interval (0 = rotate only on failure). wsTLS is always on (the pool is a wss set).
// warmStandby keeps a second edge fully handshaked in the background for instant failover.
func DialWSPool(dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, pool *wsPool, rotate time.Duration, xhttp bool, xhMode string, warmStandby bool) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, wsTLS: true, xhttp: xhttp, xhMode: xhMode, pool: pool, rotate: rotate, warmStandby: warmStandby,
		idle: idleFor(keepalive), isClient: true, addr: "pool", closeCh: make(chan struct{})}, nil
}

// newWSPoolFromCfg builds a pool from the config's clean IP/SNI lists (decoding each
// SNI's base64 ECH), or returns nil when no pool is configured.
func newWSPoolFromCfg(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) *wsPool {
	if len(ips) == 0 || len(snis) == 0 {
		return nil
	}
	return newWSPool(ips, snis, autoBurn, statusPath)
}

// DialXHTTP (client role) is DialWS over the xhttp carrier: it reaches the edge with the
// same wss/ECH/Host, but carries the stream over a GET(down)+POST(up) pair rather than a
// WebSocket upgrade, so it passes a CDN that blocks WebSocket.
func DialXHTTP(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher, wsHost, wsPath string, wsTLS bool, wsECH []byte, xhMode string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, xhttp: true, xhMode: xhMode, wsHost: wsHost, wsPath: wsPath, wsTLS: wsTLS, wsECH: wsECH,
		idle: idleFor(keepalive), isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// ListenXHTTP (server role) serves the xhttp endpoint over plain HTTP (a CDN in front
// terminates TLS). A non-session request gets a plausible 404.
func ListenXHTTP(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string) (*TCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, xhttp: true, idle: idleFor(keepalive), addr: listenAddr, ln: ln, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns), xhSessions: make(map[string]*xhttpSession)}, nil
}

// ListenWS (server role) accepts WebSocket connections (plain HTTP upgrade; a CDN
// in front terminates TLS and forwards the WebSocket to us). A non-WS request gets
// a plausible 404 and is dropped, so the port looks like an ordinary web endpoint.
func ListenWS(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string) (*TCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, idle: idleFor(keepalive), addr: listenAddr, ln: ln, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns)}, nil
}

// ListenTCP (server role) binds listenAddr and accepts connections. When cover is
// set it builds a REALITY responder that authenticates our clients by a token in
// their ClientHello and transparently proxies every other connection (probes,
// scanners, the censor) to the real coverSNI:443, so active probing sees that
// site's genuine certificate.
func ListenTCP(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, cover bool, coverSNI string) (*TCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	b := &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		cover: cover, coverSNI: coverSNI,
		idle: idleFor(keepalive), addr: listenAddr, ln: ln, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns)}
	if cover {
		// coverSNI is required (validated in config); it is the real site the
		// server borrows and proxies non-authenticated connections to.
		b.coverSrv, err = tlscover.NewServer(psk, coverSNI)
		if err != nil {
			ln.Close()
			return nil, err
		}
	}
	return b, nil
}

// Run blocks until Close is called. The TUN reader runs for the whole lifetime;
// the connection side either accepts (server) or dials-with-retry (client).
func (b *TCP) Run() error {
	go b.tunLoop()
	if b.isClient {
		go b.keepaliveLoop()
		if b.pool != nil {
			go b.retestLoop() // background health retests with exponential backoff
		} else if b.pp != nil || b.sp != nil {
			go b.peerPinPollLoop() // direct pp/sp pools: apply operator pins from the node's cmd file
		}
		if b.warmStandby && b.pool != nil {
			b.dialLoopWarm() // make-before-break: active + warm standby
		} else {
			b.dialLoop()
		}
	} else if b.xhttp {
		b.runXHTTPServer()
	} else {
		b.acceptLoop()
	}
	return nil
}

// Close stops the carrier and unblocks Run.
func (b *TCP) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	close(b.closeCh)
	if s := b.httpSrv.Load(); s != nil {
		s.Close()
	}
	if b.ln != nil {
		b.ln.Close()
	}
	if c := b.cur.Load(); c != nil {
		c.conn.Close()
	}
	if c := b.standby.Load(); c != nil { // warm-standby carrier, if any
		c.conn.Close()
	}
	return nil
}

// newFramer builds a connFramer with NO sealer yet. In clear mode it stays nil;
// in crypto mode the ephemeral handshake installs the session sealer before any
// framed data is read or written.
func (b *TCP) newFramer(conn net.Conn) *connFramer {
	return &connFramer{conn: conn, r: bufio.NewReaderSize(conn, readBufSize), obfs: b.obfs, psk: b.psk}
}

// clientHandshake (client) sends an init and reads the responder's reply, then
// installs the ephemeral session sealer. Runs under the caller's read deadline.
func (b *TCP) clientHandshake(cf *connFramer) error {
	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		return err
	}
	if _, err := cf.conn.Write(crypto.InitMsg(b.psk, ci)); err != nil {
		return err
	}
	resp := make([]byte, crypto.HandshakeSize)
	if _, err := io.ReadFull(cf.r, resp); err != nil {
		return err
	}
	eResp, err := crypto.ParseResp(b.psk, ci.Pub, resp)
	if err != nil {
		return err
	}
	s, err := crypto.SessionSealer(b.cipher, b.psk, ci, eResp, ci.Pub, eResp, true)
	if err != nil {
		return err
	}
	cf.sealer = s
	return nil
}

// serverHandshake (server) reads an init, authenticates it, installs the session
// sealer, and replies. A wrong PSK / probe fails ParseInit and gets no response.
func (b *TCP) serverHandshake(cf *connFramer) error {
	init := make([]byte, crypto.HandshakeSize)
	if _, err := io.ReadFull(cf.r, init); err != nil {
		return err
	}
	eInit, err := crypto.ParseInit(b.psk, init)
	if err != nil {
		return err
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return err
	}
	s, err := crypto.SessionSealer(b.cipher, b.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return err
	}
	cf.sealer = s
	_, err = cf.conn.Write(crypto.RespMsg(b.psk, eInit, sr))
	return err
}

// acceptLoop (server) hands each new connection to a per-connection goroutine.
// On a transient Accept error (e.g. EMFILE from an fd flood) it backs off briefly
// instead of busy-spinning the CPU and flooding the log.
func (b *TCP) acceptLoop() {
	var backoff time.Duration
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			if b.closed.Load() {
				return
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			log.Printf("core/tcp: accept error: %v (backoff %v)", err, backoff)
			if b.sleep(backoff) {
				return
			}
			continue
		}
		backoff = 0
		go b.handleServerConn(conn)
	}
}

// handleServerConn serves one accepted connection. Whenever crypto is on (obfs
// or plain TCP) the connection is authenticated BEFORE it is published as live:
// the first frame must AEAD-open and pass anti-replay, so an unauthenticated
// peer (a probe, a port scan, `nc`) can no longer evict the real client by
// simply connecting. In obfs mode the salt is also withheld until then, so the
// server stays invisible to an active probe. Only clear mode (no crypto) — which
// offers no authentication by definition — publishes at once.
func (b *TCP) handleServerConn(conn net.Conn) {
	// Take a pre-auth permit; shed load if too many handshakes are already in
	// flight. The permit is released the moment the connection becomes live
	// (authenticated), so it only bounds the UNAUTHENTICATED window, never the
	// long-lived established connection.
	select {
	case b.preAuth <- struct{}{}:
	default:
		conn.Close()
		return
	}
	acquired := true
	release := func() {
		if acquired {
			acquired = false
			<-b.preAuth
		}
	}
	defer release()

	if b.ws && !b.xhttp { // WebSocket upgrade; a non-WS probe gets a 404 and is dropped
		// (xhttp is excluded: its conn already carries core frames — the HTTP GET/POST pair
		// or the single full-duplex request replaced the WS upgrade — so a ws handshake here
		// would misread the client's core handshake as an HTTP request and drop the session.)
		r, werr := wsServerHandshake(conn, time.Now().Add(handshakeTimeout))
		if werr != nil {
			conn.Close()
			return
		}
		conn = &wsConn{Conn: conn, r: r, client: false}
	} else if b.cover { // REALITY cover: authenticate by ClientHello token, else proxy to dest
		tconn, err := b.coverSrv.Handle(conn, time.Now().Add(handshakeTimeout))
		if err != nil {
			// ErrProbe: the relay goroutine now owns conn (proxying it to the
			// real site) — must NOT close it here. Any other error is fatal.
			if err != tlscover.ErrProbe {
				conn.Close()
			}
			return
		}
		conn = tconn
	}
	cf := b.newFramer(conn)
	if !b.cryptoOn {
		log.Printf("core/tcp: peer connected from %s (clear)", conn.RemoteAddr())
		b.publishServerConn(cf)
		release()
		b.serve(cf)
		return
	}
	// crypto on: run the ephemeral handshake, then read+authenticate the first
	// framed message silently before publishing. A wrong PSK / probe fails the
	// handshake and is dropped in silence. A SHORT handshake deadline (not the
	// 60 s idle) bounds the pre-auth hold.
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if err := b.serverHandshake(cf); err != nil {
		conn.Close()
		return
	}
	typ, session, seq, payload, err := cf.readFrame()
	if err != nil || !cf.rp.ok(session, seq) {
		conn.Close() // probe / wrong PSK / replay: no reply, no log noise
		return
	}
	if b.obfs {
		if err := cf.sendSalt(); err != nil { // authenticated — now answer
			conn.Close()
			return
		}
	}
	log.Printf("core/tcp: peer connected from %s", conn.RemoteAddr())
	b.publishServerConn(cf)
	release() // authenticated: no longer occupies a pre-auth slot
	b.handleFrame(cf, typ, payload)
	b.serve(cf)
}

// publishServerConn (server) registers a freshly-authenticated connection. It does NOT evict
// the previous one: a warm-standby client keeps a second live carrier up, so a new connect must
// not tear down the active tunnel. The new conn becomes the downstream target only if there is
// no downstream yet (CompareAndSwap on nil) — so a single connection behaves exactly as before,
// while a warm standby never steals downstream just by connecting. From here the downstream
// target follows the connection the client last sent a DATA frame on (see handleFrame). The
// conn is tracked in authConns and, when over maxAuthConns, the oldest idle one is reaped.
func (b *TCP) publishServerConn(cf *connFramer) {
	b.cur.CompareAndSwap(nil, cf)
	b.authMu.Lock()
	b.authConns = append(b.authConns, cf)
	cur := b.cur.Load()
	var reap []*connFramer
	for len(b.authConns) > maxAuthConns {
		idx := -1
		for i, c := range b.authConns {
			if c != cur { // never reap the live downstream target
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		reap = append(reap, b.authConns[idx])
		b.authConns = append(b.authConns[:idx], b.authConns[idx+1:]...)
	}
	b.authMu.Unlock()
	for _, v := range reap {
		v.conn.Close() // its serve loop errors out -> onConnErr cleans up cur/authConns
	}
}

// removeAuthConn drops a connection from the server's authenticated set (called from onConnErr).
// A no-op on the client, whose authConns is always empty.
func (b *TCP) removeAuthConn(cf *connFramer) {
	b.authMu.Lock()
	for i, c := range b.authConns {
		if c == cf {
			b.authConns = append(b.authConns[:i], b.authConns[i+1:]...)
			break
		}
	}
	b.authMu.Unlock()
}

// noteECHSelfHeal runs after a SUCCESSFUL in-band ECH self-heal on the LIVE carrier. It persists
// the fresh key so the next reconnect stops re-healing (no repeat rejection), and surfaces the
// event to the panel exactly once per rotation — via the edge pool (multi-edge) or, for a single
// fixed edge, the status file. A no-op emit when neither sink exists.
func (b *TCP) noteECHSelfHeal(host string, ech []byte) {
	detail := host + " " + base64.StdEncoding.EncodeToString(ech)
	if b.pool != nil {
		if b.pool.updateECH(host, ech) { // persist onto the matching SNI; emit only on a real change
			b.pool.event("ech", "self_heal", detail)
		}
		return
	}
	// Single edge: wsECH is touched only by the one dial-loop goroutine, so this needs no lock.
	// Persist the fresh key and emit once per actual change (the next connect presents it directly).
	if !bytes.Equal(b.wsECH, ech) {
		b.wsECH = ech
		b.st.event("ech", "self_heal", detail) // nil-safe: a no-op when no status file is wired
	}
}

// tlsToEdge performs the client-side TLS handshake to the CDN edge over an
// already-dialed conn, using uTLS with a Chrome fingerprint so the ClientHello is
// indistinguishable from a real browser's (Go's crypto/tls has a distinctive JA3
// a censor can block even under ECH). ServerName=wsHost is the SNI; when wsECH is
// set that SNI is encrypted (ECH) — uTLS carries the real ECH inside the
// Chrome-shaped hello, so we keep both the fingerprint and the hidden SNI. If the
// edge rejects a stale ECH config it returns a fresh RetryConfigList — we redial
// once and retry with it, so Cloudflare's periodic ECH-key rotation self-heals
// without a rebuild. On any failure the passed (or redialed) conn is closed.
func (b *TCP) tlsToEdge(conn net.Conn, dialAddr, host string, ech []byte, live bool) (net.Conn, error) {
	var err error
	healed := false // set once we redial with a fresh RetryConfigList
	for attempt := 0; attempt < 2; attempt++ {
		var uc net.Conn
		// ALPN forced to http/1.1: the WebSocket upgrade that follows (wsClientHandshake) is
		// HTTP/1.1, so the edge must not pick h2.
		uc, err = uEdgeHandshake(b.fragWrap(conn, host), host, ech, []string{"http/1.1"}) // split the ClientHello's SNI when enabled
		if err == nil {
			if healed && live { // live self-heal: persist the fresh key and surface it (pool or single-edge)
				b.noteECHSelfHeal(host, ech)
			}
			return uc, nil
		}
		conn.Close()
		var echErr *utls.ECHRejectionError
		if attempt == 0 && errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			ech = echErr.RetryConfigList // stale ECH key: redial and retry with the fresh one
			log.Printf("core/ws: ECH self-heal for %s (%s) — stale key rejected, retrying with fresh key %s",
				host, dialAddr, base64.StdEncoding.EncodeToString(ech))
			healed = true
			if conn, err = b.dialer(10*time.Second).Dial("tcp", dialAddr); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	return nil, err
}

// uEdgeHandshake performs one client-side uTLS handshake to a CDN edge over conn, presenting a
// current-Chrome ClientHello so our JA3 matches a real browser's — Go's crypto/tls does not, a gap
// ECH cannot close (ECH hides the SNI, not the fingerprint). ServerName=host is the SNI; when ech
// is set uTLS injects the real Encrypted ClientHello in place of Chrome's GREASE-ECH, keeping BOTH
// the fingerprint and the hidden SNI. A stale ECH key surfaces as a *utls.ECHRejectionError with a
// fresh RetryConfigList for the caller's self-heal. Shared by the ws (tlsToEdge) and xhttp carriers.
func uEdgeHandshake(conn net.Conn, host string, ech []byte, alpn []string) (net.Conn, error) {
	cfg := &utls.Config{ServerName: host}
	if len(ech) > 0 {
		cfg.EncryptedClientHelloConfigList = ech
	}
	uc := utls.UClient(conn, cfg, utls.HelloCustom)
	spec, err := chromeSpec(alpn)
	if err != nil {
		return nil, err
	}
	if err = uc.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err = uc.Handshake(); err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return uc, nil
}

// chromeSpec returns a freshly built current-Chrome ClientHelloSpec. When alpn is non-nil it
// overrides Chrome's ALPN VALUES (Chrome offers [h2, http/1.1]) — we force ["http/1.1"] for the
// WebSocket/packet-up carriers so the edge does not pick h2, and pass nil for the grpc carrier to
// keep Chrome's h2. Only the ALPN values change, not the extension SET, so the JA3 still matches
// Chrome (the ApplicationSettings extension keeps its authentic h2; only ALPN drives negotiation).
// UTLSIdToSpec builds a fresh spec each call, so mutating its ALPN cannot disturb a shared parrot;
// the spec keeps Chrome's GREASE-ECH placeholder, which uTLS replaces with real ECH when a config
// carries an ECHConfigList.
func chromeSpec(alpn []string) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return spec, err
	}
	if alpn != nil {
		for _, ext := range spec.Extensions {
			if a, ok := ext.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = alpn
			}
		}
	}
	return spec, nil
}

// establishWS opens one WebSocket connection: it picks the current pool edge (or the
// single configured edge), dials it, does the wss TLS+ECH, and performs the upgrade.
// In pool mode ANY failure is handed to attributeFailure, which runs a differential probe
// to decide by TRUTH — not a guess — whether the IP, the SNI, or neither is at fault, and
// pulls the guilty axis into the health FSM. A successful connect clears both axes.
func (b *TCP) establishWS() (net.Conn, string, string, error) {
	dialAddr, host, ech, path := b.addr, b.wsHost, b.wsECH, b.wsPath
	if b.pool != nil {
		ip, sni, ok := b.pool.current()
		if !ok {
			return nil, "", "", errors.New("ws: edge pool is empty")
		}
		dialAddr, host, ech, path = ip, sni.host, sni.ech, sni.path
	}
	if host == "" {
		host = dialAddr
	}
	sniEnt := wsSNIEntry{host: host, ech: ech, path: path} // for failure attribution / probes
	conn, err := b.dialer(10*time.Second).Dial("tcp", dialAddr)
	if err != nil {
		b.attributeFailure(dialAddr, sniEnt) // differential probe: IP vs SNI vs transient
		return nil, dialAddr, "", err
	}
	if b.wsTLS {
		tc, terr := b.tlsToEdge(conn, dialAddr, host, ech, true) // live carrier: a self-heal is panel-worthy
		if terr != nil {
			b.attributeFailure(dialAddr, sniEnt)
			return nil, dialAddr, "", terr
		}
		conn = tc
	}
	r, werr := wsClientHandshake(conn, host, path, time.Now().Add(handshakeTimeout))
	if werr != nil {
		conn.Close()
		b.attributeFailure(dialAddr, sniEnt)
		return nil, dialAddr, "", werr
	}
	if b.pool != nil {
		b.pool.succeeded(dialAddr, host) // combo works: clear any suspicion on this IP and SNI
	}
	return &wsConn{Conn: conn, r: r, client: true}, dialAddr, activeLabel(dialAddr, host), nil
}

// probeVerdict is the outcome of a differential failure probe: which axis of a failed
// (ip, sni) combo is actually at fault.
type probeVerdict int

const (
	verdictUnknown   probeVerdict = iota // no healthy alternative answered -> blame nothing
	verdictTransient                     // the same combo worked on retry -> a blip, blame nothing
	verdictIPGuilty                      // a healthy SNI proved the IP the culprit
	verdictSNIGuilty                     // a healthy IP proved the SNI the culprit
)

// probeEdge does a quick TCP dial + TLS handshake to (ip, sni) — presenting that SNI with its
// ECH — then closes: NO WebSocket upgrade, NO data. It reports only whether the edge completes
// a TLS session for that SNI, which is exactly the signal the health FSM needs. Used by both
// the differential failure probe and the retest scheduler. (Pool clients always run wss, so a
// TLS probe is a valid reachability test for ws and xhttp edges alike.)
func (b *TCP) probeEdge(ip string, sni wsSNIEntry) bool {
	conn, err := b.dialer(probeTimeout).Dial("tcp", ip)
	if err != nil {
		return false
	}
	host := sni.host
	if host == "" {
		host = ip
	}
	tc, err := b.tlsToEdge(conn, ip, host, sni.ech, false) // probe: don't emit a self-heal event
	if err != nil {
		return false
	}
	tc.Close()
	return true
}

// probeEdgeFull is a higher-fidelity reachability probe than probeEdge: it completes the FULL
// client control path to (ip, sni) — TCP + (wss TLS+ECH) + WebSocket UPGRADE — then closes, with
// no data and no pool-state changes. Because a LIVE success requires the upgrade (not just TLS),
// using this for retests/attribution stops a broken ws/origin path (TLS completes, upgrade 502s
// — the steady state of a dead origin behind a CDN that terminates TLS for anyone) from being
// mislabeled "reachable" the way a TLS-only probe would, and from falsely healing a suspect.
// For xhttp edges (no ws upgrade) it falls back to the TLS-only probeEdge.
func (b *TCP) probeEdgeFull(ip string, sni wsSNIEntry) bool {
	if b.xhttp {
		return b.probeEdge(ip, sni)
	}
	conn, err := b.dialer(probeTimeout).Dial("tcp", ip)
	if err != nil {
		return false
	}
	host := sni.host
	if host == "" {
		host = ip
	}
	if b.wsTLS {
		tc, terr := b.tlsToEdge(conn, ip, host, sni.ech, false) // probe: don't emit a self-heal event
		if terr != nil {
			return false
		}
		conn = tc
	}
	path := sni.path
	if path == "" {
		path = "/"
	}
	_, werr := wsClientHandshake(conn, host, path, time.Now().Add(handshakeTimeout))
	conn.Close()
	return werr == nil
}

// differentialProbe attributes a failed (ip, sni) connect to a specific axis. It is
// REPRODUCE-FIRST and deterministic (no race), because the old racing version blamed a
// random axis whenever every edge was actually reachable — a transient blip could sideline
// a perfectly good IP purely on goroutine scheduling. The steps:
//
//  1. Re-probe the EXACT failing combo. If it works now, the failure was a transient blip
//     (or an origin/ws-upgrade issue that TLS-probing can't see) -> blame nothing.
//  2. The combo is confirmed down. Change ONE variable against a KNOWN-HEALTHY partner:
//     - healthy IP + failSNI still works  -> the SNI is fine, so the IP is guilty
//     - healthy IP + failSNI also fails    -> the SNI itself is blocked -> SNI guilty
//     (and symmetrically via a healthy SNI when no alternate IP exists).
//  3. If both isolated probes fail though both partners are healthy, the IP and SNI are both
//     down: pin the IP (the coarser axis); the SNI heals on its own retest.
//
// With no healthy alternative on either axis (a single edge) there is nowhere to move and
// nothing to compare, so the verdict is UNKNOWN — blame nothing.
func (b *TCP) differentialProbe(failIP string, failSNI wsSNIEntry) probeVerdict {
	probe := b.probeEdgeFull // full TLS+ws-upgrade path, so a dead origin isn't read as "reachable"
	if b.probeFn != nil {
		probe = b.probeFn
	}
	// 1. Reproduce. A working combo means the original failure was transient — do NOT blame
	// an axis (this is what stops good edges from flapping into "suspect").
	if probe(failIP, failSNI) {
		return verdictTransient
	}
	// 2. Isolate: does the IP work with a known-good SNI? does the SNI work on a known-good IP?
	// A reachability is only KNOWN when a healthy partner exists to test it against.
	altIP, hasAltIP := b.pool.altHealthyIP(failIP)
	altSNI, hasAltSNI := b.pool.altHealthySNI(failSNI.host)
	ipOK, ipKnown := false, hasAltSNI
	if hasAltSNI {
		ipOK = probe(failIP, altSNI) // failIP with a healthy SNI
	}
	sniOK, sniKnown := false, hasAltIP
	if hasAltIP {
		sniOK = probe(altIP, failSNI) // failSNI on a healthy IP
	}
	// 3. Decide by which isolated variable still works. Only POSITIVE evidence pins a verdict.
	switch {
	case sniKnown && sniOK && !(ipKnown && ipOK):
		return verdictIPGuilty // the SNI works elsewhere but the IP doesn't -> IP is the culprit
	case ipKnown && ipOK && !(sniKnown && sniOK):
		return verdictSNIGuilty // the IP works elsewhere but the SNI doesn't -> SNI is the culprit
	case ipKnown && !ipOK && sniKnown && !sniOK:
		// Both isolated probes failed though both partners are FSM-healthy: either both edges
		// are genuinely blocked, OR the client's own uplink just dropped. Confirm with a
		// KNOWN-GOOD combo before blaming, so a local/broad outage never falsely burns a clean
		// edge (which is exactly the false-positive this whole rewrite exists to prevent).
		if probe(altIP, altSNI) {
			return verdictIPGuilty // uplink is fine -> both edges really are down; pin the IP (SNI heals on retest)
		}
		return verdictUnknown // even a known-good combo fails -> local/broad outage; blame nothing
	default:
		return verdictUnknown // both work in isolation (ambiguous/origin), or nothing to compare
	}
}

// attributeFailure runs the differential probe for a failed pool combo and moves the guilty
// axis (if any) into suspect. A no-op when there is no pool or autoBurn is off (nothing would
// be marked, so the probe traffic is skipped).
func (b *TCP) attributeFailure(ip string, sni wsSNIEntry) {
	if b.pool == nil || !b.pool.autoBurn {
		return
	}
	switch b.differentialProbe(ip, sni) {
	case verdictIPGuilty:
		b.pool.markSuspect("ip", ip, "ip_blocked") // IP unreachable while a healthy SNI worked elsewhere
	case verdictSNIGuilty:
		b.pool.markSuspect("sni", sni.host, "sni_blocked") // SNI failed even on a healthy IP (DPI on ClientHello)
	}
	// transient / unknown: mark nothing
}

// setLastErr records the CAUSE of a client carrier death for the pool's "down" event. It ignores
// "use of closed network connection" (that is us closing it, a consequence not a cause) and never
// downgrades a real cause already stored for this death to that placeholder.
func (b *TCP) setLastErr(err error) {
	if err == nil {
		return
	}
	s := err.Error()
	if strings.Contains(s, "use of closed network connection") {
		return
	}
	b.lastErr.Store(s)
}

// takeLastErr returns and clears the last recorded death cause.
func (b *TCP) takeLastErr() string {
	s, _ := b.lastErr.Load().(string)
	b.lastErr.Store("")
	return s
}

// classifyErr maps a raw carrier death cause to a stable reason CODE the panel renders into text.
// The point is a PRECISE, core-observed reason (it saw the actual error) rather than a panel guess.
func classifyErr(s string) string {
	l := strings.ToLower(s)
	switch {
	case s == "":
		return "closed"
	case strings.Contains(l, "keepalive") || strings.Contains(l, "ping"):
		return "ping_timeout" // no keepalive answer: throttled/blackholed, or the peer went away
	case strings.Contains(l, "connection reset") || strings.Contains(l, "reset by peer"):
		return "reset" // RST — often a stateful-DPI kill of an established flow
	case strings.Contains(l, "refused"):
		return "refused"
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline") || strings.Contains(l, "no route") || strings.Contains(l, "unreachable"):
		return "timeout"
	case strings.Contains(l, "eof"):
		return "eof"
	case strings.Contains(l, "tls") || strings.Contains(l, "handshake") || strings.Contains(l, "certificate"):
		return "tls" // TLS failed — a blocked SNI is often killed at the ClientHello
	case strings.Contains(l, "websocket") || strings.Contains(l, "ws ") || strings.Contains(l, "101") || strings.Contains(l, "upgrade"):
		return "ws_upgrade" // reached TLS but the CDN/origin refused the upgrade
	default:
		return "dropped"
	}
}

// retestLoop (pooled client) periodically retests suspect/dead pool entries whose backoff has
// elapsed. Each due entry is probed against a known-healthy partner (or the active one), and
// the outcome walks the entry's FSM (success -> healthy, failure -> longer backoff / dead), so
// a temporary block heals itself with no rebuild. Runs until Close.
func (b *TCP) retestLoop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			if kind, key, ok := b.pool.readSelectCmd(); ok { // panel "pin this edge" request
				log.Printf("core/ws: select edge %s=%s (panel pin)", kind, key)
				b.SelectEdge(kind, key)
			}
			for _, spec := range b.pool.dueRetests() {
				if b.closed.Load() {
					return
				}
				// Full TLS+ws-upgrade probe so a suspect isn't falsely healed by a TLS-only success
				// on an edge whose ws/origin path is actually broken.
				b.pool.retestResult(spec.kind, spec.key, b.probeEdgeFull(spec.ip, spec.sni))
			}
		}
	}
}

// dialLoop (client) keeps a connection to the server alive, retrying on drop. For a
// ws pool it rotates edges: each attempt uses the pool's current (IP × SNI), a
// failure burns the offending IP/SNI (establishWS), and a proactive timer tears the
// connection down after b.rotate so the client moves before the edge is fingerprinted.
func (b *TCP) dialLoop() {
	// direct-tcp peer/source pools: burnDest burns+advances the destination and, once the dest pool has
	// cycled through every endpoint against the current source, walks the source too (same policy as the
	// datagram carriers' rotationController). succeedBoth clears transient burns after a healthy session.
	destRot := 0
	burnDest := func() {
		if (b.pp != nil && b.pp.isPinned()) || (b.sp != nil && b.sp.isPinned()) {
			return // an operator pin freezes failover: current()/sourceIP() force the pinned endpoint
		}
		if b.pp != nil {
			b.pp.fail()
			if destRot++; b.sp != nil && b.pp.size() > 0 && destRot >= b.pp.size() {
				b.rotateSourceTCP(false)
				destRot = 0
			}
		} else if b.sp != nil {
			b.rotateSourceTCP(false)
		}
	}
	succeedBoth := func() {
		destRot = 0
		if b.pp != nil {
			b.pp.succeeded()
		}
		if b.sp != nil {
			b.sp.succeeded()
		}
	}
	for {
		if b.closed.Load() {
			return
		}
		conn, label, combo, err := b.dialCarrier() // logs the specific transport failure itself
		if err != nil {
			if b.pool != nil {
				b.pool.advance() // rotate to the next combo for the retry
			} else {
				burnDest() // direct-tcp: this endpoint won't connect -> burn + advance (dest, then source)
			}
			if b.sleep(1 * time.Second) {
				return
			}
			continue
		}
		cf, err := b.handshakeAndPrime(conn)
		if err != nil {
			conn.Close()
			if b.sleep(1 * time.Second) {
				return
			}
			continue
		}
		log.Printf("core/tcp: connected to %s", label)
		connectedAt := time.Now()
		b.cur.Store(cf)
		cc := conn
		b.curConn.Store(&cc) // expose the live conn so RotateIP/RotateSNI can drop it
		if b.pool != nil {
			// Record the edge we ACTUALLY connected on as the live active and flush the status
			// file, so a plain rotation reflects the new active immediately (the panel reads this
			// field and logs the auto-switch off its change). setActive is the single writer of the
			// active edge — current() no longer touches it, so a standby dial can't corrupt it.
			b.pool.setActive(combo)
		} else {
			// Direct pp/sp: we just connected on the current endpoints, so release any operator pin that
			// has now landed (a pin behaves as "jump here and keep trying until connected"). Guard on
			// isPinned so current() is consulted only while a pin forces it (it then returns the pinned
			// endpoint with no cur movement); in the no-pin steady state this is a cheap skip.
			if b.pp != nil && b.pp.isPinned() {
				b.pp.pinApplied(b.pp.current())
			}
			if b.sp != nil && b.sp.isPinned() {
				b.sp.pinApplied(b.sp.current())
			}
		}
		// Proactive rotation: after b.rotate, advance the pool and drop this connection
		// so dialLoop reconnects on the next edge. A connection that dies on its own
		// keeps the same edge — the timer is stopped before that path runs.
		var rot *time.Timer
		var rotated atomic.Bool
		if b.pool != nil && b.rotate > 0 && !b.pool.isPinned() { // a pin freezes the edge: no auto-rotation
			c := conn
			rot = time.AfterFunc(b.rotate, func() { rotated.Store(true); b.pool.advance(); c.Close() })
		} else if (b.pp != nil && b.pp.rotate > 0) || (b.sp != nil && b.sp.rotate > 0) {
			c := conn
			iv := time.Duration(0) // fire on whichever pool has the (longer) rotate interval set
			if b.pp != nil {
				iv = b.pp.rotate
			}
			if b.sp != nil && b.sp.rotate > iv {
				iv = b.sp.rotate
			}
			// Only tear the live connection down if a pool ACTUALLY advanced. When every other endpoint
			// is burned (the common "one IP got filtered" steady state) rotateOnce() can't move; closing
			// anyway would drop a healthy connection every interval for nothing (cf. the datagram guard).
			rot = time.AfterFunc(iv, func() {
				if (b.pp != nil && b.pp.isPinned()) || (b.sp != nil && b.sp.isPinned()) {
					return // an operator pin freezes proactive rotation until it lands or its TTL lapses
				}
				moved := false
				if b.pp != nil {
					if _, m := b.pp.rotateOnce(); m {
						moved = true
					}
				}
				if b.rotateSourceTCP(true) { // advances the source pool; re-dial applies the new LocalAddr
					moved = true
				}
				if moved {
					rotated.Store(true)
					c.Close()
				}
			})
		}
		b.serve(cf) // blocks until this connection dies
		if rot != nil {
			rot.Stop()
		}
		b.curConn.CompareAndSwap(&cc, nil)
		b.cur.CompareAndSwap(cf, nil)
		// Classify why this carrier died and feed the pool's health + event log. A drop we caused
		// ourselves — an operator pin/rotate, or a scheduled proactive rotation — is NOT a failure
		// and is not logged as "down". A genuine death records a precise core-observed "down" reason
		// and updates data-plane health (short session -> throttle fault + move off; sustained -> ok).
		if b.pool != nil && !b.closed.Load() {
			cause := b.takeLastErr()
			if b.manualSwitch.Swap(false) || rotated.Load() {
				b.pool.dataSuccess(label) // deliberate, healthy switch — confirm the edge was fine
			} else {
				b.pool.down(classifyErr(cause), label) // arms the paired "up" the next reconnect emits
				if time.Since(connectedAt) < minLiveness {
					b.pool.dataFailure(label)
					b.pool.advance() // don't re-stick on the bad edge
				} else {
					b.pool.dataSuccess(label)
				}
			}
		} else if (b.pp != nil || b.sp != nil) && !b.closed.Load() {
			// Direct-tcp peer/source pool: a scheduled proactive rotation is deliberate (clear any
			// transient burns); a genuine death that came too soon means the endpoint connected but
			// couldn't carry data (throttle/blackhole) — burn + advance off it (and walk the source once
			// dests cycle). A death after a healthy lifetime is an ordinary drop (server restart): keep
			// the endpoints and clear stale burns.
			if rotated.Load() {
				succeedBoth()
			} else if time.Since(connectedAt) < minLiveness {
				burnDest()
			} else {
				succeedBoth()
			}
		}
		if b.sleep(1 * time.Second) {
			return
		}
	}
}

// dialCarrier opens the transport connection for ONE dial attempt: a pool/single ws or xhttp
// edge (with failure attribution inside establishWS/establishXHTTP), or a plain/cover TCP dial.
// It returns the live conn and a label for logging, and logs the specific transport-level
// failure itself so callers only decide retry/rotation policy. It does NOT frame or handshake.
func (b *TCP) dialCarrier() (net.Conn, string, string, error) {
	if b.ws { // pool or single edge: dial + wss(+ECH) + upgrade, burning on failure
		var c net.Conn
		var edge, combo string
		var err error
		if b.xhttp {
			c, edge, combo, err = b.establishXHTTP()
		} else {
			c, edge, combo, err = b.establishWS()
		}
		if err != nil {
			log.Printf("core/ws: connect via %s failed: %v", edge, err)
			return nil, edge, "", err
		}
		return c, edge, combo, nil
	}
	target := b.dialTarget() // the rotation pool's current endpoint, or the fixed peer
	c, err := b.dialer(10*time.Second).Dial("tcp", target)
	if err != nil {
		log.Printf("core/tcp: dial %s failed: %v", target, err)
		return nil, target, "", err
	}
	if b.cover { // wrap in a Chrome-fingerprinted TLS session carrying the auth token
		tconn, cerr := tlscover.ClientConn(c, b.coverSNI, b.psk, time.Now().Add(handshakeTimeout))
		if cerr != nil {
			c.Close()
			log.Printf("core/tcp: tls cover to %s failed: %v", target, cerr)
			return nil, target, "", cerr
		}
		c = tconn
	}
	return c, target, target, nil
}

// handshakeAndPrime wraps a freshly-dialed conn in a framer, runs the client ephemeral handshake
// (crypto) and the obfs salt exchange, then primes the server with a ping that authenticates us.
// On any failure the returned error is non-nil and the caller closes conn. On success the framer
// is fully established and ready for serve/readLoop.
func (b *TCP) handshakeAndPrime(conn net.Conn) (*connFramer, error) {
	// Desync the DPI as early as possible: inject decoy TCP segments on the freshly-connected
	// 4-tuple before our own handshake bytes flow. Best-effort, kernel connection untouched.
	b.sendTCPFakes(conn)
	cf := b.newFramer(conn)
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if b.cryptoOn { // ephemeral handshake first: establishes the session sealer
		if err := b.clientHandshake(cf); err != nil {
			return nil, err
		}
	}
	if b.obfs {
		if err := cf.sendSalt(); err != nil { // client speaks first (length-mask salt)
			return nil, err
		}
	}
	_ = cf.writeFrame(typePing, nil) // prime + authenticate us to the server
	return cf, nil
}

// warmEstablish makes ONE full dial+handshake+prime attempt for the warm-standby path. When
// advance is true it rotates the pool first, so a standby lands on a different edge than the
// active. On success the pool status file is flushed (as dialLoop does on connect). On a
// transport failure the pool is advanced so the next attempt tries a different combo.
func (b *TCP) warmEstablish(advance bool) (*connFramer, net.Conn, string, string, error) {
	if advance && b.pool != nil {
		b.pool.advance()
	}
	conn, label, combo, err := b.dialCarrier()
	if err != nil {
		if b.pool != nil {
			b.pool.advance() // move off the failing edge for the next attempt
		}
		return nil, nil, label, "", err
	}
	cf, err := b.handshakeAndPrime(conn)
	if err != nil {
		conn.Close()
		return nil, nil, label, "", err
	}
	if b.pool != nil {
		b.pool.writeStatus() // flush any health/burn state this dial discovered (NOT the active edge)
	}
	return cf, conn, label, combo, nil
}

// warmConn bundles a freshly-established carrier framer with its underlying conn (and the edge
// label it dialed), handed from a background dial worker to the warm-standby manager.
type warmConn struct {
	cf    *connFramer
	conn  net.Conn
	label string // the edge IP (health accounting)
	combo string // the full "ip · sni" for the status file's live active edge
}

// dialLoopWarm is the make-before-break client loop for a ws edge pool: it keeps the ACTIVE
// carrier (b.cur) and a fully-handshaked warm STANDBY (b.standby, to another edge) up at once.
// On the active's failure or a proactive rotation the standby is promoted atomically — a single
// b.cur swap; the next TUN packet flips the server's downstream via downstream-follows-data — and
// a fresh standby is then built in the background, so the TUN never waits on a cold dial. If no
// standby is ready when the active dies it falls back to a fresh dial that runs in the BACKGROUND
// (dialActiveAsync -> activeReady) so the select loop stays responsive to rotation/pins during a
// full outage — the startup dial is the only blocking one. ALL pointer transitions happen in THIS
// goroutine; network dials run in
// workers that hand their result back over buffered channels, so b.cur/b.standby are mutated from
// exactly one place — no data races.
func (b *TCP) dialLoopWarm() {
	exits := make(chan *connFramer, 8)    // a per-conn reader finished (its conn died)
	ready := make(chan warmConn, 2)       // a background standby dial completed
	activeReady := make(chan warmConn, 2) // a background ACTIVE (re)dial completed (outage/failover path)
	// On exit, close any carrier that a dial worker managed to buffer just as Close fired (its own
	// select preferred the send over closeCh) — otherwise that conn's fd would leak until process exit.
	defer func() {
		for {
			select {
			case wc := <-ready:
				wc.conn.Close()
			case wc := <-activeReady:
				wc.conn.Close()
			default:
				return
			}
		}
	}()
	var active, standby *connFramer
	// Track the active carrier's edge + when it started carrying data, so a promoted-then-quickly-
	// dead edge is attributed to the right IP for data-plane throttle detection (C1).
	var activeLabel, standbyLabel string
	// The full "ip · sni" combo of each carrier, for the status file's live active edge. Kept
	// separate from activeLabel (the IP, used for health accounting) and threaded per-dial so a
	// standby build can never overwrite the live active — only setActive/promote publish it.
	var activeCombo, standbyCombo string
	var activeSince time.Time
	standbyBuilding := false
	activeBuilding := false // an async fresh-active dial is in flight (outage/failover) — keeps the select loop responsive

	// startReader runs a connection's read loop; on exit it reports the framer so the manager
	// can react (promote / rebuild). The report is abandoned if Close fired.
	startReader := func(cf *connFramer) {
		go func() {
			b.setLastErr(b.readLoop(cf)) // capture the death cause for a precise pool "down" reason
			cf.conn.Close()
			select {
			case exits <- cf:
			case <-b.closeCh:
			}
		}()
	}
	setActive := func(cf *connFramer, conn net.Conn, label, combo string) {
		active = cf
		activeLabel = label
		activeCombo = combo
		activeSince = time.Now()
		b.cur.Store(cf)
		cc := conn
		b.curConn.Store(&cc)
		if b.pool != nil {
			b.pool.setActive(combo)                                          // publish the live active edge + flush the status file
			b.pool.pinApplied(label, strings.TrimPrefix(combo, label+" · ")) // a pin that targeted this edge is now satisfied
		}
		startReader(cf)
	}
	// requestStandby dials a new standby in the background unless one is already up or building.
	// The result arrives on `ready`; a persistent failure retries with a short backoff until a
	// standby comes up or Close fires.
	requestStandby := func() {
		if standby != nil || standbyBuilding {
			return
		}
		standbyBuilding = true
		go func() {
			for {
				if b.closed.Load() {
					return
				}
				cf, conn, label, combo, err := b.warmEstablish(true) // different edge than the active
				if err != nil {
					if b.sleep(1 * time.Second) {
						return
					}
					continue
				}
				select {
				case ready <- warmConn{cf, conn, label, combo}:
				case <-b.closeCh:
					conn.Close()
				}
				return
			}
		}()
	}
	// promote swaps the warm standby into the active slot and retires the old active. Returns
	// false when there is no standby ready to promote.
	promote := func() bool {
		if standby == nil {
			return false
		}
		old := active
		// Proactive rotation retires a still-live active — count its sustained session as healthy
		// so its edge isn't wrongly suspected. (On a FAILOVER the caller has already nil'd active
		// and accounted for its death, so old==nil here and this is skipped.)
		if old != nil && activeLabel != "" && time.Since(activeSince) >= minLiveness {
			b.pool.dataSuccess(activeLabel)
		}
		active = standby
		activeLabel = standbyLabel
		activeCombo = standbyCombo
		activeSince = time.Now() // the standby starts carrying data now
		standbyLabel = ""
		standbyCombo = ""
		b.cur.Store(standby) // instant failover; the next TUN packet flips the server downstream
		if sc := b.standbyConn.Load(); sc != nil {
			b.curConn.Store(sc)
		}
		standby = nil
		b.standby.Store(nil)
		b.standbyConn.Store(nil)
		if b.pool != nil {
			b.pool.setActive(activeCombo) // the promoted standby is now the live edge — publish + flush
			b.pool.pinApplied(activeLabel, strings.TrimPrefix(activeCombo, activeLabel+" · "))
		}
		if old != nil {
			old.conn.Close() // retire the old edge; its reader reports an (ignored) exit
		}
		return true
	}
	// dialActiveBlocking establishes a fresh active with a short retry backoff, used at startup
	// and as the fallback when the active dies with no warm standby ready. Returns false if Close
	// fired during the retry.
	dialActiveBlocking := func() bool {
		for {
			if b.closed.Load() {
				return false
			}
			cf, conn, label, combo, err := b.warmEstablish(false)
			if err != nil {
				if b.sleep(1 * time.Second) {
					return false
				}
				continue
			}
			log.Printf("core/tcp: connected to %s", label)
			setActive(cf, conn, label, combo)
			return true
		}
	}
	// dialActiveAsync (re)establishes a fresh active in the BACKGROUND — the outage/failover
	// counterpart to dialActiveBlocking. It keeps the manager's select loop live so proactive
	// rotation ticks, standby-ready reports and (crucially) operator pins keep being serviced while
	// every edge is unreachable: each retry re-reads current(), so a pin placed mid-outage is honored
	// the moment its edge recovers. The result arrives on activeReady; at most one runs at a time.
	dialActiveAsync := func() {
		if activeBuilding || b.closed.Load() {
			return
		}
		activeBuilding = true
		go func() {
			for {
				if b.closed.Load() {
					return
				}
				cf, conn, label, combo, err := b.warmEstablish(false)
				if err != nil {
					if b.sleep(1 * time.Second) {
						return
					}
					continue
				}
				select {
				case activeReady <- warmConn{cf, conn, label, combo}:
				case <-b.closeCh:
					conn.Close()
				}
				return
			}
		}()
	}

	if !dialActiveBlocking() {
		return
	}
	requestStandby()

	var rotateC <-chan time.Time
	if b.rotate > 0 {
		rt := time.NewTicker(b.rotate)
		defer rt.Stop()
		rotateC = rt.C
	}

	for {
		select {
		case <-b.closeCh:
			return
		case ex := <-exits:
			switch ex {
			case active:
				// Was this drop an operator pin / manual rotate (rotate1)? If so it is NOT a fault,
				// and we must NOT promote the pre-built standby — that standby is on a DIFFERENT edge
				// and would ignore the operator's choice (the reported "pick #3, #2 goes active" bug).
				manual := b.manualSwitch.Swap(false)
				cause := b.takeLastErr()
				if !manual && activeLabel != "" {
					// Genuine failure: log a precise core-observed "down" reason and attribute
					// data-plane health (short-lived -> throttle fault; sustained -> confirm healthy).
					b.pool.down(classifyErr(cause), activeLabel) // arms the paired "up" the next reconnect emits
					if time.Since(activeSince) < minLiveness {
						b.pool.dataFailure(activeLabel)
					} else {
						b.pool.dataSuccess(activeLabel)
					}
				}
				b.cur.CompareAndSwap(active, nil)
				b.curConn.Store(nil)
				active = nil
				if manual {
					// Re-dial the ACTIVE from current() so it lands on the exact edge the operator
					// selected. Drop the stale standby (wrong edge) so it is rebuilt off the new one.
					if standby != nil {
						standby.conn.Close()
						standby = nil
						standbyLabel = ""
						b.standby.Store(nil)
						b.standbyConn.Store(nil)
						standbyBuilding = false
					}
					log.Printf("core/tcp: manual pin/rotate — re-dialing active on the selected edge")
					dialActiveAsync() // warmEstablish(false) -> current() -> the pinned edge; non-blocking, requestStandby fires on activeReady
				} else if promote() {
					log.Printf("core/tcp: active carrier failed — promoted warm standby")
					requestStandby()
				} else {
					log.Printf("core/tcp: active carrier failed with no warm standby — dialing fresh (background)")
					dialActiveAsync() // non-blocking so the loop keeps servicing rotation/pins during the outage
				}
			case standby:
				// Standby died before promotion: drop and rebuild.
				standby = nil
				b.standby.CompareAndSwap(ex, nil)
				b.standbyConn.Store(nil)
				standbyBuilding = false
				requestStandby()
			default:
				// A retired/old conn we already moved past — nothing to do.
			}
		case wc := <-ready:
			standbyBuilding = false
			if b.closed.Load() {
				wc.conn.Close()
				continue
			}
			if active == nil {
				// Mid-outage this standby is already up while the async active dial is still retrying —
				// adopt it as the ACTIVE now instead of discarding it and waiting; the in-flight async
				// dial is harmlessly dropped when it lands (activeReady guards on active!=nil).
				log.Printf("core/tcp: adopting ready standby as active during outage")
				setActive(wc.cf, wc.conn, wc.label, wc.combo)
				requestStandby()
				continue
			}
			if standby != nil {
				wc.conn.Close() // no longer needed (promoted/replaced meanwhile)
				continue
			}
			standby = wc.cf
			standbyLabel = wc.label
			standbyCombo = wc.combo
			b.standby.Store(wc.cf)
			sc := wc.conn
			b.standbyConn.Store(&sc)
			startReader(wc.cf)
		case wc := <-activeReady:
			// A background outage/failover active dial finished. Adopt it as the live active (unless we
			// somehow already have one — e.g. a ready standby was adopted meanwhile — or we're closing)
			// and start warming a standby again.
			activeBuilding = false
			if active != nil || b.closed.Load() {
				wc.conn.Close()
				continue
			}
			// Consume any stale manual-switch flag: a pin placed mid-outage (while active==nil) set it
			// with no exit to consume it; the fresh active already honored that pin via current(), so
			// clear it now or the NEXT genuine death would be mis-read as a manual switch.
			b.manualSwitch.Store(false)
			log.Printf("core/tcp: connected to %s", wc.label)
			setActive(wc.cf, wc.conn, wc.label, wc.combo)
			requestStandby()
		case <-rotateC:
			// Proactive make-before-break rotation: promote the warm standby and retire the old
			// active, then build a fresh standby. If none is ready yet, skip this tick — the next
			// one rotates once the standby has warmed (never drop the only live carrier). An operator
			// pin freezes the edge, so proactive rotation is skipped entirely while pinned.
			if b.pool != nil && b.pool.isPinned() {
				continue
			}
			if promote() {
				log.Printf("core/tcp: proactive rotation — promoted warm standby")
				requestStandby()
			}
		}
	}
}

// RotateIP / RotateSNI are the live "rotate now" controls for a ws edge pool: they advance
// a single dimension and drop the current carrier connection, so dialLoop immediately
// re-dials on the new edge. The TUN device stays up throughout (only the sub-second carrier
// redial happens) — no rebuild, no interface teardown. No-op unless this is a pooled client.
func (b *TCP) RotateIP()  { b.rotate1(func() { b.pool.advanceIP() }) }
func (b *TCP) RotateSNI() { b.rotate1(func() { b.pool.advanceSNI() }) }

// ProbeNow forces an immediate retest of a pool entry (kind "ip"|"sni") on the retest
// scheduler's next tick — backs a panel/node "probe now" control. No-op unless pooled.
func (b *TCP) ProbeNow(kind, key string) {
	if b.pool != nil {
		b.pool.probeNow(kind, key)
	}
}

// ProbeAllNow forces an immediate retest of every suspect/dead pool entry (backs the
// panel "probe now" button, delivered as a signal that carries no key). No-op unless pooled.
func (b *TCP) ProbeAllNow() {
	if b.pool != nil {
		b.pool.probeAllNow()
	}
	if b.pp != nil {
		b.pp.probeAllNow()
	}
	if b.sp != nil {
		b.sp.probeAllNow()
	}
}

// peerPinPollLoop polls the direct destination/source pools' cmd files on a 1s ticker; a pending pin
// pins the requested endpoint and drops the live carrier so dialLoop immediately re-dials onto it
// (dialTarget()/sourceIP() read the pinned endpoint via the pool's current()). No rebuild — the TUN
// stays up. Runs until Close. The ws edge pool uses retestLoop for the same job on its own axes.
func (b *TCP) peerPinPollLoop() {
	drop := func() {
		b.manualSwitch.Store(true) // operator-initiated: skip fault accounting on the induced drop
		if c := b.curConn.Load(); c != nil {
			(*c).Close() // unblocks serve(); dialLoop re-dials on the pinned endpoint
		}
	}
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			if b.pp != nil {
				if key, ok := b.pp.readSelectCmd(); ok && b.pp.selectEntry(key) {
					log.Printf("core/tcp: pin destination %s (panel select)", key)
					drop()
				}
			}
			if b.sp != nil {
				if key, ok := b.sp.readSelectCmd(); ok && b.sp.selectEntry(key) {
					log.Printf("core/tcp: pin source %s (panel select)", key)
					drop()
				}
			}
		}
	}
}

// SelectEdge pins a specific pool edge (kind "ip"|"sni", key its value) as the active one and
// drops the live carrier so dialLoop immediately re-dials onto it — the TUN stays up. This is
// the exact-jump behind the panel's per-edge pin button (delivered via the node's cmd file,
// since a signal can't carry the key). No-op unless pooled.
func (b *TCP) SelectEdge(kind, key string) {
	if b.pool == nil {
		return
	}
	b.rotate1(func() { b.pool.selectEntry(kind, key) })
}

func (b *TCP) rotate1(step func()) {
	if b.pool == nil {
		return
	}
	step()
	b.manualSwitch.Store(true) // operator-initiated: skip fault accounting; warm loop re-dials via current()
	if c := b.curConn.Load(); c != nil {
		(*c).Close() // unblocks serve(); dialLoop re-dials on the advanced/pinned edge
	}
}

// handleFrame dispatches a single decoded frame.
func (b *TCP) handleFrame(cf *connFramer, typ byte, payload []byte) {
	switch typ {
	case typePing:
		_ = cf.writeFrame(typePong, nil)
	case typePong:
		// keepalive ack
	case typeData:
		// Downstream follows upstream DATA (server only): the connection the client most
		// recently sent a real data frame on becomes the TUN->client target, so a warm standby
		// (which only sends keepalive pings) never steals downstream, and a promotion flips the
		// server within one frame with no explicit signaling. Ping/pong must NOT move it.
		if !b.isClient {
			b.cur.Store(cf)
		}
		if _, err := b.dev.Write(payload); err != nil {
			log.Printf("core/tcp: tun write error: %v", err)
		}
	}
}

// serve reads framed messages from one connection until it errors or closes.
// onConnErr clears the live pointer on exit, so both the client (which redials)
// and the server converge on "no live connection" without extra bookkeeping.
// The read deadline is refreshed every frame in ALL modes so a peer that dies
// without a FIN/RST is reaped instead of pinning a goroutine forever.
func (b *TCP) serve(cf *connFramer) {
	b.onConnErr(cf, b.readLoop(cf))
}

// readLoop reads framed messages from one connection until it errors or closes, dispatching
// each to handleFrame. It does NOT touch b.cur/authConns, so the warm-standby manager can run
// it directly in a per-connection goroutine and own the pointer transitions itself; serve wraps
// it with onConnErr for the single-connection client and every server connection. The read
// deadline is refreshed every frame in ALL modes so a peer that dies without a FIN/RST is
// reaped instead of pinning a goroutine forever.
func (b *TCP) readLoop(cf *connFramer) error {
	for {
		cf.conn.SetReadDeadline(time.Now().Add(b.idle))
		typ, session, seq, payload, err := cf.readFrame()
		if err != nil {
			return err
		}
		cf.unanswered.Store(0) // any inbound frame proves the peer is alive -> reset ping-loss
		if cf.sealer != nil && !cf.rp.ok(session, seq) {
			continue // authenticated but replayed -> ignore, keep the connection
		}
		b.handleFrame(cf, typ, payload)
	}
}

func (b *TCP) onConnErr(cf *connFramer, err error) {
	if b.isClient {
		b.setLastErr(err) // remember the cause so dialLoop can log a precise pool "down" reason
	}
	cf.conn.Close()
	b.cur.CompareAndSwap(cf, nil) // only clear downstream if THIS conn was the target
	b.removeAuthConn(cf)          // server: drop from the authenticated set (no-op on the client)
	if !b.closed.Load() {
		log.Printf("core/tcp: connection closed: %v", err)
	}
}

// tunLoop reads L3 packets from TUN and writes them to whichever connection is
// currently live. Packets that arrive while no connection is up are dropped
// (the peer retransmits at the L4 layer).
func (b *TCP) tunLoop() {
	buf := make([]byte, maxDatagram)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			if !b.closed.Load() {
				log.Printf("core/tcp: tun read error: %v", err)
			}
			return
		}
		cf := b.cur.Load()
		if cf == nil {
			continue // no live peer connection yet
		}
		if err := cf.writeFrame(typeData, buf[:n]); err != nil {
			b.onConnErr(cf, err)
		}
	}
}

// keepaliveLoop (client) pings the server over the live connection so idle
// tunnels do not get reaped by stateful middleboxes. In obfs mode the period is
// jittered so it does not emit on a fixed clock.
func (b *TCP) keepaliveLoop() {
	for {
		// Jitter in ALL modes: a fixed keepalive clock is a passive timing
		// fingerprint even without obfs framing.
		select {
		case <-b.closeCh:
			return
		case <-time.After(jitter(b.keepalive)):
			if cf := b.cur.Load(); cf != nil {
				if ok, err := b.pingOne(cf); !ok {
					if b.warmStandby {
						// Let the warm-standby manager react to the reader's exit (promote a
						// standby) rather than tearing down b.cur out from under it here.
						b.setLastErr(err) // record the cause before we close (startReader would only see "closed")
						cf.conn.Close()
					} else {
						if err == errPingTimeout {
							log.Printf("core/tcp: %d keepalive pings unanswered — dropping stale connection", pingLossThreshold)
						}
						b.onConnErr(cf, err)
					}
				}
			}
			// Keepalive must cover the warm STANDBY too, so it is not idle-reaped by the server
			// and per-connection ping-loss detection works on it. A failed standby is just
			// closed; its reader exit tells the manager to rebuild it.
			if b.warmStandby {
				if sb := b.standby.Load(); sb != nil {
					if ok, _ := b.pingOne(sb); !ok {
						sb.conn.Close()
					}
				}
			}
		}
	}
}

// pingOne sends one keepalive ping on cf and advances its ping-loss counter. It returns ok=false
// when the connection should be dropped: a write error (returned as err) or too many unanswered
// pings (errPingTimeout). A silently black-holed connection trips the latter well before the idle
// deadline. readLoop resets the counter on any inbound frame.
func (b *TCP) pingOne(cf *connFramer) (ok bool, err error) {
	if err := cf.writeFrame(typePing, nil); err != nil {
		return false, err
	}
	if cf.unanswered.Add(1) >= pingLossThreshold {
		return false, errPingTimeout
	}
	return true, nil
}

// sleep waits d or returns true if Close fired during the wait.
func (b *TCP) sleep(d time.Duration) bool {
	select {
	case <-b.closeCh:
		return true
	case <-time.After(d):
		return false
	}
}
