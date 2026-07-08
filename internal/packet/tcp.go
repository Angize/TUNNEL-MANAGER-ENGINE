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
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

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
)

var errDesync = errors.New("core/tcp: stream desync")

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

	// xhttp carrier (transport "ws" with ws_xhttp): the core stream rides an HTTP request
	// pair (packet-up: GET-down + seq-POSTs-up) or a single full-duplex request
	// (stream-one) instead of a WebSocket upgrade, so it passes CDNs that block WebSocket.
	// Same fronting fields (wsHost/wsTLS/wsECH/wsPath) apply. Because the client carries
	// core frames directly over these requests (the HTTP layer replaces the WS upgrade),
	// the server must NOT run wsServerHandshake on an xhttp conn — see handleServerConn.
	xhttp      bool
	xhMode     string       // client: "stream" (single full-duplex request) else packet-up
	xhTLS      *tls.Config  // test-only: overrides the client edge TLS config (nil in production)
	httpSrv    *http.Server // server: the xhttp endpoint (nil otherwise)
	xhMu       sync.Mutex
	xhSessions map[string]*xhttpSession

	isClient bool
	addr     string // server: listen addr; client: peer addr
	bindIP   string // client: source IP to dial FROM (empty = kernel default); tcp/ws/xhttp only

	ln      net.Listener
	cur     atomic.Pointer[connFramer] // currently live connection (nil when none)
	curConn atomic.Pointer[net.Conn]   // client+pool: the live carrier conn, closed to force a re-dial on rotation
	closed  atomic.Bool
	closeCh chan struct{}
	preAuth chan struct{} // permits: caps concurrent unauthenticated handlers
}

// SetSourceIP pins the client's outbound dials to a specific source IP (the node's own
// registered IP), so on a multi-IP host the peer/CDN sees that IP instead of the kernel's
// default primary. No effect on the server side or on raw/flux carriers. Call before Run.
func (b *TCP) SetSourceIP(ip string) { b.bindIP = ip }

// dialer returns a net.Dialer that, when a source IP is pinned, binds the outbound socket to
// it (LocalAddr). A malformed or non-local IP is ignored (falls back to the kernel default).
func (b *TCP) dialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if b.bindIP != "" {
		if ip := net.ParseIP(b.bindIP); ip != nil {
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
func DialWSPool(dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, pool *wsPool, rotate time.Duration, xhttp bool, xhMode string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, wsTLS: true, xhttp: xhttp, xhMode: xhMode, pool: pool, rotate: rotate,
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
		b.dialLoop()
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
	if b.httpSrv != nil {
		b.httpSrv.Close()
	}
	if b.ln != nil {
		b.ln.Close()
	}
	if c := b.cur.Load(); c != nil {
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
		if old := b.cur.Swap(cf); old != nil {
			old.conn.Close()
		}
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
	if old := b.cur.Swap(cf); old != nil {
		old.conn.Close()
	}
	release() // authenticated: no longer occupies a pre-auth slot
	b.handleFrame(cf, typ, payload)
	b.serve(cf)
}

// tlsToEdge performs the client-side TLS handshake to the CDN edge over an
// already-dialed conn. ServerName=wsHost is the SNI; when wsECH is set that SNI
// is encrypted (ECH) so only a benign public name is visible on the wire. If the
// edge rejects a stale ECH config it returns a fresh RetryConfigList — we redial
// once and retry with it, so Cloudflare's periodic ECH-key rotation self-heals
// without a rebuild. On any failure the passed (or redialed) conn is closed.
func (b *TCP) tlsToEdge(conn net.Conn, dialAddr, host string, ech []byte) (net.Conn, error) {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		cfg := &tls.Config{ServerName: host}
		if len(ech) > 0 {
			cfg.EncryptedClientHelloConfigList = ech
		}
		tc := tls.Client(conn, cfg)
		tc.SetDeadline(time.Now().Add(handshakeTimeout))
		if err = tc.Handshake(); err == nil {
			var zero time.Time
			tc.SetDeadline(zero)
			return tc, nil
		}
		conn.Close()
		var echErr *tls.ECHRejectionError
		if attempt == 0 && errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			ech = echErr.RetryConfigList // stale ECH key: redial and retry with the fresh one
			if conn, err = b.dialer(10 * time.Second).Dial("tcp", dialAddr); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	return nil, err
}

// establishWS opens one WebSocket connection: it picks the current pool edge (or the
// single configured edge), dials it, does the wss TLS+ECH, and performs the upgrade.
// In pool mode a failure is classified and the offending IP or SNI is burned before
// the error is returned, so dialLoop advances to the next edge on retry:
//
//	dial timeout / refused → the IP is unreachable/blocked  → burn IP
//	TLS handshake failure  → the SNI drew a reset (or bad cert) → burn SNI
//	WS upgrade not 101      → the domain/zone/account blocks WS → burn SNI
func (b *TCP) establishWS() (net.Conn, string, error) {
	dialAddr, host, ech, path := b.addr, b.wsHost, b.wsECH, b.wsPath
	if b.pool != nil {
		ip, sni, ok := b.pool.current()
		if !ok {
			b.pool.resetBurns() // every combo burned — fresh cycle so we never dead-end
			if ip, sni, ok = b.pool.current(); !ok {
				return nil, "", errors.New("ws: edge pool is empty")
			}
		}
		dialAddr, host, ech, path = ip, sni.host, sni.ech, sni.path
	}
	if host == "" {
		host = dialAddr
	}
	conn, err := b.dialer(10 * time.Second).Dial("tcp", dialAddr)
	if err != nil {
		if b.pool != nil {
			b.pool.burnIP(dialAddr)
		}
		return nil, dialAddr, err
	}
	if b.wsTLS {
		tc, terr := b.tlsToEdge(conn, dialAddr, host, ech)
		if terr != nil {
			if b.pool != nil {
				b.pool.burnSNI(host)
			}
			return nil, dialAddr, terr
		}
		conn = tc
	}
	r, werr := wsClientHandshake(conn, host, path, time.Now().Add(handshakeTimeout))
	if werr != nil {
		conn.Close()
		if b.pool != nil {
			b.pool.burnSNI(host)
		}
		return nil, dialAddr, werr
	}
	return &wsConn{Conn: conn, r: r, client: true}, dialAddr, nil
}

// dialLoop (client) keeps a connection to the server alive, retrying on drop. For a
// ws pool it rotates edges: each attempt uses the pool's current (IP × SNI), a
// failure burns the offending IP/SNI (establishWS), and a proactive timer tears the
// connection down after b.rotate so the client moves before the edge is fingerprinted.
func (b *TCP) dialLoop() {
	for {
		if b.closed.Load() {
			return
		}
		var conn net.Conn
		label := b.addr
		if b.ws { // pool or single edge: dial + wss(+ECH) + upgrade, burning on failure
			var c net.Conn
			var edge string
			var err error
			if b.xhttp {
				c, edge, err = b.establishXHTTP()
			} else {
				c, edge, err = b.establishWS()
			}
			if err != nil {
				log.Printf("core/ws: connect via %s failed: %v", edge, err)
				if b.sleep(1 * time.Second) {
					return
				}
				continue
			}
			conn, label = c, edge
		} else {
			c, err := b.dialer(10 * time.Second).Dial("tcp", b.addr)
			if err != nil {
				log.Printf("core/tcp: dial %s failed: %v", b.addr, err)
				if b.sleep(1 * time.Second) {
					return
				}
				continue
			}
			if b.cover { // wrap in a Chrome-fingerprinted TLS session carrying the auth token
				tconn, cerr := tlscover.ClientConn(c, b.coverSNI, b.psk, time.Now().Add(handshakeTimeout))
				if cerr != nil {
					c.Close()
					log.Printf("core/tcp: tls cover to %s failed: %v", b.addr, cerr)
					if b.sleep(1 * time.Second) {
						return
					}
					continue
				}
				c = tconn
			}
			conn = c
		}
		cf := b.newFramer(conn)
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		if b.cryptoOn { // ephemeral handshake first: establishes the session sealer
			if err := b.clientHandshake(cf); err != nil {
				conn.Close()
				if b.sleep(1 * time.Second) {
					return
				}
				continue
			}
		}
		if b.obfs {
			if err := cf.sendSalt(); err != nil { // client speaks first (length-mask salt)
				conn.Close()
				if b.sleep(1 * time.Second) {
					return
				}
				continue
			}
		}
		log.Printf("core/tcp: connected to %s", label)
		b.cur.Store(cf)
		cc := conn
		b.curConn.Store(&cc) // expose the live conn so RotateIP/RotateSNI can drop it
		if b.pool != nil {
			// current() set the active (ip · sni) in memory when it picked this edge, but
			// only burns flushed it to the status file — so a plain rotation left the file
			// stale and the panel kept showing the old active row. Flush it on every connect.
			b.pool.writeStatus()
		}
		_ = cf.writeFrame(typePing, nil) // prime + authenticate us to the server
		// Proactive rotation: after b.rotate, advance the pool and drop this connection
		// so dialLoop reconnects on the next edge. A connection that dies on its own
		// keeps the same edge — the timer is stopped before that path runs.
		var rot *time.Timer
		if b.pool != nil && b.rotate > 0 {
			c := conn
			rot = time.AfterFunc(b.rotate, func() { b.pool.advance(); c.Close() })
		}
		b.serve(cf) // blocks until this connection dies
		if rot != nil {
			rot.Stop()
		}
		b.curConn.CompareAndSwap(&cc, nil)
		b.cur.CompareAndSwap(cf, nil)
		if b.sleep(1 * time.Second) {
			return
		}
	}
}

// RotateIP / RotateSNI are the live "rotate now" controls for a ws edge pool: they advance
// a single dimension and drop the current carrier connection, so dialLoop immediately
// re-dials on the new edge. The TUN device stays up throughout (only the sub-second carrier
// redial happens) — no rebuild, no interface teardown. No-op unless this is a pooled client.
func (b *TCP) RotateIP()  { b.rotate1(func() { b.pool.advanceIP() }) }
func (b *TCP) RotateSNI() { b.rotate1(func() { b.pool.advanceSNI() }) }

func (b *TCP) rotate1(step func()) {
	if b.pool == nil {
		return
	}
	step()
	if c := b.curConn.Load(); c != nil {
		(*c).Close() // unblocks serve(); dialLoop re-dials on the advanced edge
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
	for {
		cf.conn.SetReadDeadline(time.Now().Add(b.idle))
		typ, session, seq, payload, err := cf.readFrame()
		if err != nil {
			b.onConnErr(cf, err)
			return
		}
		if cf.sealer != nil && !cf.rp.ok(session, seq) {
			continue // authenticated but replayed -> ignore, keep the connection
		}
		b.handleFrame(cf, typ, payload)
	}
}

func (b *TCP) onConnErr(cf *connFramer, err error) {
	cf.conn.Close()
	b.cur.CompareAndSwap(cf, nil)
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
				if err := cf.writeFrame(typePing, nil); err != nil {
					b.onConnErr(cf, err)
				}
			}
		}
	}
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
