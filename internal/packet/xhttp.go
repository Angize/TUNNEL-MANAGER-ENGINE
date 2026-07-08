// xhttp carrier: the bip stream rides plain HTTP requests instead of a WebSocket upgrade, so
// it passes through CDNs that block or don't proxy WebSocket (e.g. a Cloudflare account with
// WebSocket disabled) while still looking like ordinary HTTPS.
//
//	downstream (server -> client): one long-lived GET whose streaming response body carries
//	                               the sealed frames.
//	upstream   (client -> server): PACKET-UP — each write is a short, discrete POST carrying one
//	                               chunk plus a monotonic seq. A CDN like Cloudflare buffers a
//	                               single long streaming request body (which stalled the
//	                               handshake), but forwards short complete POSTs immediately; the
//	                               server reassembles them by seq into the upstream byte stream.
//	correlation: a random session id in the query ties the GET and the POSTs together.
//
// Both directions present a byte stream, so xhttpConn is a net.Conn and the existing connFramer
// (length-prefix + AEAD + obfs + keepalive) rides on top unchanged — exactly as over raw TCP, a
// TLS-cover, or a WebSocket conn. The same fronting fields as ws apply (host/edge/ECH/path); the
// server stays plain (the CDN terminates TLS).
package packet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const xhttpUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// maxXhChunk caps a single upstream POST body so a hostile client can't force a huge alloc.
const maxXhChunk = 1 << 20

// strAddr is a net.Addr for an xhttp conn (there is no single socket behind it).
type strAddr string

func (a strAddr) Network() string { return "xhttp" }
func (a strAddr) String() string  { return string(a) }

// xhttpConn presents the GET(down) + packet-up(POSTs) pair (client) or the reassembled upstream
// pipe + downstream ResponseWriter (server) as a single net.Conn. On the client, Write goes to
// the packet-up sender (up); on the server, Write goes to the GET response writer (w). Read
// deadlines are honoured by an idle timer that closes the conn when it fires.
type xhttpConn struct {
	r     io.Reader
	w     io.Writer
	flush func()
	up    *xhUp // client only: packet-up upstream sender (nil on the server)

	wmu     sync.Mutex
	mu      sync.Mutex
	closed  bool
	closeFn func()
	idle    *time.Timer
	ra, la  net.Addr
}

func (c *xhttpConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *xhttpConn) Write(p []byte) (int, error) {
	if c.up != nil { // client: each write becomes a short POST with a seq
		return c.up.write(p)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n, err := c.w.Write(p)
	if err == nil && c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *xhttpConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.idle != nil {
		c.idle.Stop()
	}
	fn := c.closeFn
	c.mu.Unlock()
	// Closing the reader is what actually unblocks a Read parked in c.r.Read — closeFn tears the
	// session down but does not interrupt an in-flight body/pipe read. Both readers (http body,
	// io.PipeReader) implement io.Closer and return an error to the blocked reader on close.
	if rc, ok := c.r.(io.Closer); ok {
		rc.Close()
	}
	if fn != nil {
		fn()
	}
	return nil
}

func (c *xhttpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if c.idle != nil {
		c.idle.Stop()
		c.idle = nil
	}
	if !t.IsZero() {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		c.idle = time.AfterFunc(d, func() { c.Close() })
	}
	return nil
}

func (c *xhttpConn) SetWriteDeadline(time.Time) error { return nil }
func (c *xhttpConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *xhttpConn) LocalAddr() net.Addr              { return c.la }
func (c *xhttpConn) RemoteAddr() net.Addr             { return c.ra }

func randSID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func xhttpPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	return p
}

// --- client: packet-up upstream --------------------------------------------------------------

type seqChunk struct {
	seq  uint64
	data []byte
}

// xhUp is the client's packet-up upstream. Each Write is copied, tagged with a monotonic seq,
// and handed to a small pool of workers that POST it as a short, complete request; the server
// reassembles by seq. A single long streaming POST is what a CDN buffers — short discrete POSTs
// are forwarded at once, so the handshake and data flow through Cloudflare. Any POST failure
// fails the whole conn (once) so dialLoop re-dials a fresh session.
type xhUp struct {
	hc     *http.Client
	ctx    context.Context
	urlFor func(seq uint64) string
	setHdr func(*http.Request)
	seq    uint64
	ch     chan seqChunk
	fail   func()
	once   sync.Once
}

func newXhUp(ctx context.Context, hc *http.Client, urlFor func(uint64) string, setHdr func(*http.Request), fail func()) *xhUp {
	u := &xhUp{hc: hc, ctx: ctx, urlFor: urlFor, setHdr: setHdr, fail: fail, ch: make(chan seqChunk, 256)}
	for i := 0; i < 4; i++ {
		go u.worker()
	}
	return u
}

func (u *xhUp) write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	seq := atomic.AddUint64(&u.seq, 1) - 1
	select {
	case u.ch <- seqChunk{seq, b}:
		return len(p), nil
	case <-u.ctx.Done():
		return 0, io.ErrClosedPipe
	}
}

func (u *xhUp) worker() {
	for {
		select {
		case <-u.ctx.Done():
			return
		case sc := <-u.ch:
			if err := u.post(sc); err != nil {
				u.once.Do(u.fail) // kill the conn once; dialLoop re-dials a fresh session
				return
			}
		}
	}
}

func (u *xhUp) post(sc seqChunk) error {
	req, err := http.NewRequestWithContext(u.ctx, "POST", u.urlFor(sc.seq), bytes.NewReader(sc.data))
	if err != nil {
		return err
	}
	u.setHdr(req)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := u.hc.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("xhttp: up seq %d got HTTP %d", sc.seq, resp.StatusCode)
	}
	return nil
}

// xhttpEdge resolves the (dialAddr, host, ech, path) for this attempt. With an edge pool it uses
// the pool's current (IP × SNI), resetting burns if every combination is burned so the client
// never dead-ends. A single fixed edge uses the plain WSHost/WSECH/WSPath.
func (b *BipTCP) xhttpEdge() (dialAddr, host string, ech []byte, path string, err error) {
	dialAddr, host, ech, path = b.addr, b.wsHost, b.wsECH, b.wsPath
	if b.pool != nil {
		ip, sni, ok := b.pool.current()
		if !ok {
			b.pool.resetBurns() // every combo burned — fresh cycle so we never dead-end
			if ip, sni, ok = b.pool.current(); !ok {
				return "", "", nil, "", fmt.Errorf("xhttp: edge pool is empty")
			}
		}
		dialAddr, host, ech, path = ip, sni.host, sni.ech, sni.path
	}
	if host == "" {
		host = dialAddr
	}
	return dialAddr, host, ech, path, nil
}

// xhttpClientTLS builds the client TLS config for the edge: SNI = the fronting host, with ECH
// when configured. xhTLS (test-only) overrides it wholesale.
func (b *BipTCP) xhttpClientTLS(host string, ech []byte) *tls.Config {
	if b.xhTLS != nil {
		return b.xhTLS
	}
	cfg := &tls.Config{ServerName: host}
	if len(ech) > 0 {
		cfg.EncryptedClientHelloConfigList = ech
	}
	return cfg
}

// establishXHTTP (client) opens a fresh xhttp session to the edge and returns a net.Conn over it.
// Two upstream styles share the same fronting (TLS+ECH mirror wss) and the same pool rotation
// (each attempt uses the pool's current IP × SNI; a failure burns the offending IP or SNI):
//
//	packet-up (default): a long-lived downstream GET plus short seq-tagged POSTs — most
//	                     CDN-compatible, since a CDN that buffers request bodies still forwards
//	                     short complete POSTs at once.
//	stream-one (b.xhMode=="stream"): one full-duplex request (body up, response down) — needs
//	                     HTTP/2 to the edge (ws_tls) so upstream frames flush per-write.
func (b *BipTCP) establishXHTTP() (net.Conn, string, error) {
	dialAddr, host, ech, path, err := b.xhttpEdge()
	if err != nil {
		return nil, "", err
	}
	stream := b.xhMode == "stream"
	tr := &http.Transport{
		// Always dial the fixed edge, regardless of the request URL host, so the Host/SNI stays
		// the fronting domain while we connect to a specific (clean) CDN IP.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", dialAddr)
		},
		// packet-up rides HTTP/1.1 (each POST is a complete request); stream-one is full-duplex
		// and needs HTTP/2 to the edge so upstream frames flush per-write instead of buffering.
		ForceAttemptHTTP2:   stream && b.wsTLS,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8, // the streaming GET holds one conn; the packet-up POSTs reuse the rest
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: handshakeTimeout,
	}
	scheme := "http"
	if b.wsTLS {
		scheme = "https"
		tr.TLSClientConfig = b.xhttpClientTLS(host, ech)
	}
	sid := randSID()
	base := scheme + "://" + host + xhttpPath(path)
	hc := &http.Client{Transport: tr}
	ctx, cancel := context.WithCancel(context.Background())
	setHdr := func(r *http.Request) {
		r.Header.Set("User-Agent", xhttpUA)
		r.Header.Set("Accept", "*/*")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Cache-Control", "no-store")
	}
	if stream {
		return b.dialXHTTPStream(hc, tr, ctx, cancel, base, sid, dialAddr, host, setHdr)
	}
	return b.dialXHTTPPacket(hc, tr, ctx, cancel, base, sid, dialAddr, host, setHdr)
}

// dialXHTTPStream (stream-one) opens ONE full-duplex request: the request body — a pipe we feed
// on Write — carries the upstream, and the response body carries the downstream, concurrently.
// The server sends its response head immediately (before the body completes), so hc.Do returns
// and both directions flow at once. Needs HTTP/2 end-to-end so per-frame writes are flushed.
func (b *BipTCP) dialXHTTPStream(hc *http.Client, tr *http.Transport, ctx context.Context, cancel func(), base, sid, dialAddr, host string, setHdr func(*http.Request)) (net.Conn, string, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", base+"?s="+sid, pr)
	if err != nil {
		cancel()
		pw.Close()
		return nil, dialAddr, err
	}
	setHdr(req)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1 // unknown length: stream the body (h2 DATA / chunked), never buffer it whole
	resp, err := hc.Do(req)
	if err != nil {
		cancel()
		pw.Close()
		if b.pool != nil { // a transport failure (dial/TLS) points at the IP
			b.pool.burnIP(dialAddr)
		}
		return nil, dialAddr, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		pw.Close()
		if b.pool != nil { // the edge answered but rejected this domain/path — burn the SNI
			b.pool.burnSNI(host)
		}
		return nil, dialAddr, fmt.Errorf("xhttp: stream got HTTP %d (want 200)", resp.StatusCode)
	}
	conn := &xhttpConn{
		r: resp.Body, w: pw, // Write -> pipe -> request body (upstream); Read <- response body (downstream)
		ra: strAddr(dialAddr), la: strAddr("xhttp-client"),
	}
	conn.closeFn = func() { cancel(); pw.Close(); resp.Body.Close(); tr.CloseIdleConnections() }
	return conn, dialAddr, nil
}

// dialXHTTPPacket (packet-up) opens the long-lived downstream GET and starts the packet-up
// upstream sender for a fresh session, returning a net.Conn over the pair.
func (b *BipTCP) dialXHTTPPacket(hc *http.Client, tr *http.Transport, ctx context.Context, cancel func(), base, sid, dialAddr, host string, setHdr func(*http.Request)) (net.Conn, string, error) {
	greq, _ := http.NewRequestWithContext(ctx, "GET", base+"?s="+sid, nil)
	setHdr(greq)
	gresp, err := hc.Do(greq)
	if err != nil {
		cancel()
		if b.pool != nil { // a transport failure (dial/TLS) points at the IP
			b.pool.burnIP(dialAddr)
		}
		return nil, dialAddr, err
	}
	if gresp.StatusCode != http.StatusOK {
		gresp.Body.Close()
		cancel()
		if b.pool != nil { // the edge answered but rejected this domain/path — burn the SNI
			b.pool.burnSNI(host)
		}
		return nil, dialAddr, fmt.Errorf("xhttp: down got HTTP %d (want 200)", gresp.StatusCode)
	}
	urlFor := func(seq uint64) string {
		return base + "?s=" + sid + "&seq=" + strconv.FormatUint(seq, 10)
	}
	conn := &xhttpConn{
		r:  gresp.Body,
		ra: strAddr(dialAddr), la: strAddr("xhttp-client"),
	}
	conn.closeFn = func() { cancel(); gresp.Body.Close(); tr.CloseIdleConnections() }
	conn.up = newXhUp(ctx, hc, urlFor, setHdr, func() { conn.Close() })
	return conn, dialAddr, nil
}

// --- server ----------------------------------------------------------------------------------

type xhttpSession struct {
	upR   *io.PipeReader
	upW   *io.PipeWriter
	done  chan struct{}
	start sync.Once
	end   sync.Once

	upMu    sync.Mutex        // orders packet-up POSTs by seq before writing to the upstream pipe
	nextSeq uint64            // next seq we expect to hand to upW
	pend    map[uint64][]byte // out-of-order chunks waiting for the gap to fill
}

// xhttpGetOrCreate returns the session for sid, creating it (with a fresh upstream pipe and a
// watchdog that reaps a session whose GET never arrives) on first sight.
func (b *BipTCP) xhttpGetOrCreate(sid string) *xhttpSession {
	b.xhMu.Lock()
	defer b.xhMu.Unlock()
	if s := b.xhSessions[sid]; s != nil {
		return s
	}
	pr, pw := io.Pipe()
	s := &xhttpSession{upR: pr, upW: pw, done: make(chan struct{}), pend: map[uint64][]byte{}}
	b.xhSessions[sid] = s
	time.AfterFunc(handshakeTimeout, func() { // no serve started in time -> reap
		select {
		case <-s.done:
		default:
			s.close(b, sid)
		}
	})
	return s
}

// deliver feeds one packet-up chunk into the ordered upstream. Out-of-order chunks are buffered
// until the gap fills; already-delivered seqs are dropped. Writes happen under upMu so the byte
// stream stays correctly ordered even with several POSTs in flight.
func (s *xhttpSession) deliver(seq uint64, data []byte) {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	if seq < s.nextSeq {
		return // already delivered / duplicate
	}
	if len(s.pend) > 1024 { // runaway gap (a lost POST) — let the client fail + re-dial
		return
	}
	s.pend[seq] = data
	for {
		d, ok := s.pend[s.nextSeq]
		if !ok {
			break
		}
		delete(s.pend, s.nextSeq)
		s.nextSeq++
		if len(d) > 0 {
			if _, err := s.upW.Write(d); err != nil {
				return // session gone
			}
		}
	}
}

func (s *xhttpSession) close(b *BipTCP, sid string) {
	s.end.Do(func() {
		close(s.done)
		s.upW.Close()
		s.upR.Close()
		b.xhMu.Lock()
		delete(b.xhSessions, sid)
		b.xhMu.Unlock()
	})
}

// serveXHTTPStream handles a stream-one request: the single full-duplex request IS the session —
// the request body is the upstream and the response body is the downstream. No session map, seq,
// or reassembly is needed; handleServerConn runs the bip session directly on the pair, and the
// request is held open until that session ends.
func (b *BipTCP) serveXHTTPStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // ask any nginx/CDN in front not to buffer
	w.WriteHeader(http.StatusOK)
	fl.Flush() // send the response head now so the client's request returns and the duplex opens
	conn := &xhttpConn{
		r: r.Body, w: w, flush: fl.Flush,
		ra: strAddr(r.RemoteAddr), la: strAddr("xhttp-server"),
	}
	defer conn.Close()
	b.handleServerConn(conn) // the request lifetime IS the session; blocks until it ends
}

// xhttpHandler routes a session's requests. stream-one is a single full-duplex POST (no seq).
// packet-up uses a GET (downstream body, drives handleServerConn once) plus seq-tagged POSTs
// (?seq=N) fed into the upstream. The server auto-detects the style per request, so a stream
// client and a packet client both work against one endpoint regardless of its own mode setting.
func (b *BipTCP) xhttpHandler(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("s")
	if len(sid) != 32 || strings.Trim(sid, "0123456789abcdef") != "" {
		http.Error(w, "Not Found", http.StatusNotFound) // a probe/scanner sees a plain 404
		return
	}
	// stream-one: a single full-duplex POST with no seq. Route it before touching the packet-up
	// session map (which only the GET-down + seq-POST style uses).
	if r.Method == http.MethodPost && r.URL.Query().Get("seq") == "" {
		b.serveXHTTPStream(w, r)
		return
	}
	s := b.xhttpGetOrCreate(sid)
	if r.Method == http.MethodPost {
		seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		data, _ := io.ReadAll(io.LimitReader(r.Body, maxXhChunk))
		s.deliver(seq, data)
		w.WriteHeader(http.StatusNoContent) // 204: chunk accepted, session stays open
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // ask any nginx/CDN in front not to buffer
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	conn := &xhttpConn{
		r: s.upR, w: w, flush: fl.Flush,
		ra: strAddr(r.RemoteAddr), la: strAddr("xhttp-server"),
		closeFn: func() { s.close(b, sid) },
	}
	// Drive the authenticated bip session once (the GET owns the downstream writer).
	s.start.Do(func() { go b.handleServerConn(conn) })
	<-s.done // hold the GET open (streaming downstream) until the session ends
}

// runXHTTPServer serves the xhttp endpoint until Close. A non-matching path/probe gets a plain
// 404 from the handler, so the port looks like an ordinary idle web endpoint.
func (b *BipTCP) runXHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.xhttpHandler)
	b.httpSrv = &http.Server{Handler: mux}
	if err := b.httpSrv.Serve(b.ln); err != nil && !b.closed.Load() {
		log.Printf("bip/xhttp: server: %v", err)
	}
}
