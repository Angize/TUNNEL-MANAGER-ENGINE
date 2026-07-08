// xhttp carrier: the bip stream rides two plain HTTP requests instead of a WebSocket
// upgrade, so it passes through CDNs that block or don't proxy WebSocket (e.g. a
// Cloudflare account with WebSocket disabled) while still looking like ordinary HTTPS.
//
//	downstream (server -> client): one long-lived GET whose streaming response body
//	                               carries the sealed frames.
//	upstream   (client -> server): one long-lived POST whose streaming request body
//	                               carries the sealed frames.
//	correlation: a random session id in the query ties the GET and POST together.
//
// Both directions present a byte stream, so xhttpConn is a net.Conn and the existing
// connFramer (length-prefix + AEAD + obfs + keepalive) rides on top unchanged — exactly
// as it does over a raw TCP, a TLS-cover, or a WebSocket conn. The same fronting fields
// as ws apply (host/edge/ECH/path); the server stays plain (the CDN terminates TLS).
package packet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const xhttpUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// strAddr is a net.Addr for an xhttp conn (there is no single socket behind it).
type strAddr string

func (a strAddr) Network() string { return "xhttp" }
func (a strAddr) String() string  { return string(a) }

// xhttpConn presents the GET(down)+POST(up) pair (or, on the server, the upstream
// pipe + downstream ResponseWriter) as a single net.Conn. Read deadlines are honoured
// by an idle timer that closes the conn when it fires, so a dead session is reaped.
type xhttpConn struct {
	r     io.Reader
	w     io.Writer
	flush func()

	wmu     sync.Mutex
	mu      sync.Mutex
	closed  bool
	closeFn func()
	idle    *time.Timer
	ra, la  net.Addr
}

func (c *xhttpConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *xhttpConn) Write(p []byte) (int, error) {
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
	// Closing the reader is what actually unblocks a Read that is parked in
	// c.r.Read — closeFn tears the session down but does not interrupt an
	// in-flight pipe/body read. Both our readers (http body, io.PipeReader)
	// implement io.Closer and return an error to the blocked reader on close,
	// so an idle-timer deadline reliably reaps a stuck Read.
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

// establishXHTTP (client) opens the downstream GET and the upstream POST for a fresh
// session and returns a net.Conn over the pair. TLS+ECH to the edge mirror wss. When an
// edge pool is configured it rotates like establishWS: each attempt uses the pool's
// current (IP × SNI), and a failure burns the offending IP or SNI.
func (b *BipTCP) establishXHTTP() (net.Conn, string, error) {
	dialAddr, host, ech, path := b.addr, b.wsHost, b.wsECH, b.wsPath
	if b.pool != nil {
		ip, sni, ok := b.pool.current()
		if !ok {
			b.pool.resetBurns() // every combo burned — fresh cycle so we never dead-end
			if ip, sni, ok = b.pool.current(); !ok {
				return nil, "", fmt.Errorf("xhttp: edge pool is empty")
			}
		}
		dialAddr, host, ech, path = ip, sni.host, sni.ech, sni.path
	}
	if host == "" {
		host = dialAddr
	}
	tr := &http.Transport{
		// Always dial the fixed edge, regardless of the request URL host, so the Host/SNI
		// stays the fronting domain while we connect to a specific (clean) CDN IP.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", dialAddr)
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: handshakeTimeout,
	}
	scheme := "http"
	if b.wsTLS {
		scheme = "https"
		cfg := &tls.Config{ServerName: host}
		if len(ech) > 0 {
			cfg.EncryptedClientHelloConfigList = ech
		}
		tr.TLSClientConfig = cfg
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
	pr, pw := io.Pipe()
	preq, _ := http.NewRequestWithContext(ctx, "POST", base+"?s="+sid, pr)
	setHdr(preq)
	preq.Header.Set("Content-Type", "application/octet-stream")
	go func() { // the POST runs for the whole session; its body streams our upstream
		if resp, e := hc.Do(preq); e == nil {
			resp.Body.Close()
		}
		cancel()
	}()
	conn := &xhttpConn{
		r: gresp.Body, w: pw,
		ra: strAddr(dialAddr), la: strAddr("xhttp-client"),
		closeFn: func() { cancel(); gresp.Body.Close(); pw.Close(); tr.CloseIdleConnections() },
	}
	return conn, dialAddr, nil
}

// --- server ---------------------------------------------------------------------

type xhttpSession struct {
	upR   *io.PipeReader
	upW   *io.PipeWriter
	done  chan struct{}
	start sync.Once
	end   sync.Once
}

// xhttpGetOrCreate returns the session for sid, creating it (with a fresh upstream pipe
// and a watchdog that reaps a session whose GET never arrives) on first sight.
func (b *BipTCP) xhttpGetOrCreate(sid string) *xhttpSession {
	b.xhMu.Lock()
	defer b.xhMu.Unlock()
	if s := b.xhSessions[sid]; s != nil {
		return s
	}
	pr, pw := io.Pipe()
	s := &xhttpSession{upR: pr, upW: pw, done: make(chan struct{})}
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

// xhttpHandler routes the two requests of a session: GET carries the downstream body
// (and drives handleServerConn once), POST feeds the upstream body into the pipe.
func (b *BipTCP) xhttpHandler(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("s")
	if len(sid) != 32 || strings.Trim(sid, "0123456789abcdef") != "" {
		http.Error(w, "Not Found", http.StatusNotFound) // a probe/scanner sees a plain 404
		return
	}
	s := b.xhttpGetOrCreate(sid)
	if r.Method == http.MethodPost {
		_, _ = io.Copy(s.upW, r.Body) // stream client upstream until it closes the POST
		s.close(b, sid)
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

// runXHTTPServer serves the xhttp endpoint until Close. A non-matching path/probe gets
// a plain 404 from the handler, so the port looks like an ordinary idle web endpoint.
func (b *BipTCP) runXHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.xhttpHandler)
	b.httpSrv = &http.Server{Handler: mux}
	if err := b.httpSrv.Serve(b.ln); err != nil && !b.closed.Load() {
		log.Printf("bip/xhttp: server: %v", err)
	}
}
