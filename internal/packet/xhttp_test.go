package packet

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// echoXHTTP is a minimal packet-up server: it reassembles the client's seq-tagged upstream POSTs
// into an ordered byte stream and echoes it back on the session's long-lived downstream GET.
func echoXHTTP() *httptest.Server {
	type sess struct {
		pr   *io.PipeReader
		pw   *io.PipeWriter
		mu   sync.Mutex
		next uint64
		pend map[uint64][]byte
	}
	var mu sync.Mutex
	sessions := map[string]*sess{}
	get := func(sid string) *sess {
		mu.Lock()
		defer mu.Unlock()
		if s := sessions[sid]; s != nil {
			return s
		}
		pr, pw := io.Pipe()
		s := &sess{pr: pr, pw: pw, pend: map[uint64][]byte{}}
		sessions[sid] = s
		return s
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s := get(r.URL.Query().Get("s"))
		if r.Method == http.MethodPost {
			seq, _ := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
			data, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.pend[seq] = data
			for {
				d, ok := s.pend[s.next]
				if !ok {
					break
				}
				delete(s.pend, s.next)
				s.next++
				if len(d) > 0 {
					s.pw.Write(d)
				}
			}
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fl := w.(http.Flusher)
		w.WriteHeader(200)
		fl.Flush()
		go func() { <-r.Context().Done(); s.pw.Close() }() // client gone -> unblock the read loop
		buf := make([]byte, 4096)
		for {
			n, e := s.pr.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				fl.Flush()
			}
			if e != nil {
				return
			}
		}
	})
	return httptest.NewServer(mux)
}

func TestXHTTPCarrierRoundTrip(t *testing.T) {
	srv := echoXHTTP()
	defer srv.Close()
	b := &TCP{addr: srv.Listener.Addr().String(), wsPath: "/", wsTLS: false}
	conn, _, _, err := b.establishXHTTP()
	if err != nil {
		t.Fatalf("establishXHTTP: %v", err)
	}
	defer conn.Close()

	// write several framed-ish chunks upstream; expect them echoed (in order) on the downstream.
	msgs := [][]byte{[]byte("hello xhttp"), []byte("second frame"), make([]byte, 5000)}
	for i := range msgs[2] {
		msgs[2][i] = byte(i)
	}
	go func() {
		for _, m := range msgs {
			conn.Write(m)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	want := append(append([]byte("hello xhttp"), []byte("second frame")...), msgs[2]...)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(got) < len(want) {
		n, e := conn.Read(buf)
		got = append(got, buf[:n]...)
		if e != nil {
			t.Fatalf("read after %d bytes: %v", len(got), e)
		}
	}
	if string(got) != string(want) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
	t.Logf("xhttp packet-up round-tripped %d bytes both ways", len(got))
}

// xhttpInject drives one packet each way through a live xhttp tunnel and asserts it arrives
// intact — the same end-to-end path a node runs (handshake, seal/open, TUN both directions).
func xhttpInject(t *testing.T, cliCtrl, srvCtrl *os.File) {
	t.Helper()
	pkt1 := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt1) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}
	pkt2 := bytes.Repeat([]byte{0x5A}, 500)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client payload mismatch: got %d bytes", len(got))
	}
	pkt3 := bytes.Repeat([]byte{0x33}, 120)
	if _, err := cliCtrl.Write(pkt3); err != nil {
		t.Fatalf("inject client->server #2: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server #2"); !bytes.Equal(got, pkt3) {
		t.Fatalf("client->server #2 payload mismatch")
	}
}

// TestTunnelXHTTPPacketUp runs a full server<->client xhttp tunnel in packet-up mode over a real
// (plain HTTP/1.1) socket and asserts a packet traverses each way. It is the regression test for
// the server-side bug where handleServerConn ran wsServerHandshake on an xhttp conn (b.ws is set
// for xhttp): the client speaks core frames directly over the GET/POST pair, so a WS handshake
// there misreads the core handshake as an HTTP request and the tunnel connects but passes no data.
func TestTunnelXHTTPPacketUp(t *testing.T) { testTunnelXHTTP(t, "packet", false) }

// TestTunnelXHTTPPacketUpObfs is the same with the length-mask obfs handshake in play.
func TestTunnelXHTTPPacketUpObfs(t *testing.T) { testTunnelXHTTP(t, "packet", true) }

func testTunnelXHTTP(t *testing.T, mode string, obfs bool) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "xhsrv")
	cliDev, cliCtrl := tunPair(t, "xhcli")
	ka := 1 * time.Second
	addr := freeTCPPort(t)

	srv, err := ListenXHTTP(addr, srvDev, ka, obfs, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	// single-edge packet-up client over plain HTTP; host defaults to the dial addr.
	cli, err := DialXHTTP(addr, cliDev, ka, obfs, true, psk, cipher, "", "/", false, nil, mode)
	if err != nil {
		t.Fatalf("DialXHTTP: %v", err)
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(400 * time.Millisecond)
	xhttpInject(t, cliCtrl, srvCtrl)
}

// TestTunnelXHTTPStreamAlias runs a full tunnel with the legacy mode value "stream", which now
// routes to gRPC (plain stream-one was removed). It proves the alias still round-trips both ways
// over one full-duplex request against an HTTP/2 TLS edge — so old ws_xhttp_mode="stream" configs
// keep working via gRPC. (TestTunnelXHTTPGrpc covers the "grpc" value itself.)
func TestTunnelXHTTPStreamAlias(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "xhssrv")
	cliDev, cliCtrl := tunPair(t, "xhscli")
	ka := 1 * time.Second

	srv, err := ListenXHTTP("127.0.0.1:0", srvDev, ka, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.xhttpHandler)
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	go srv.Run() // starts tunLoop so the server reads its TUN; its own plain listener stays idle
	t.Cleanup(func() { ts.Close(); srv.Close() })

	cli, err := DialXHTTP(ts.Listener.Addr().String(), cliDev, ka, false, true, psk, cipher, "", "/", true, nil, "stream")
	if err != nil {
		t.Fatalf("DialXHTTP: %v", err)
	}
	cli.xhTLS = &tls.Config{InsecureSkipVerify: true} // trust the httptest cert (test only)
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	time.Sleep(600 * time.Millisecond)
	xhttpInject(t, cliCtrl, srvCtrl)
}

// TestGrpcFraming round-trips payloads through the gRPC message framing (writer -> reader) with a
// small read buffer, so it exercises the deframer's leftover-buffer path (a message split across
// several Reads) and the Hunk wrap/unwrap.
func TestGrpcFraming(t *testing.T) {
	var buf bytes.Buffer
	w := &grpcFramingWriter{w: &buf}
	msgs := [][]byte{[]byte("hello grpc"), []byte("second frame"), bytes.Repeat([]byte{0xAB}, 5000)}
	var want []byte
	for _, m := range msgs {
		if _, err := w.Write(m); err != nil {
			t.Fatalf("frame write: %v", err)
		}
		want = append(want, m...)
	}
	r := &grpcDeframingReader{r: &buf}
	got := make([]byte, 0, len(want))
	tmp := make([]byte, 128) // small on purpose: forces a 5000-byte payload across many reads
	for len(got) < len(want) {
		n, err := r.Read(tmp)
		got = append(got, tmp[:n]...)
		if err != nil {
			t.Fatalf("deframe read after %d bytes: %v", len(got), err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("grpc framing round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

// TestTunnelXHTTPGrpc runs a full tunnel in grpc mode: one full-duplex request presenting as a
// gRPC call (Content-Type application/grpc + gRPC framing) over an HTTP/2 TLS edge. Proves the
// gRPC-framed stream round-trips a packet each way.
func TestTunnelXHTTPGrpc(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "xhgsrv")
	cliDev, cliCtrl := tunPair(t, "xhgcli")
	ka := 1 * time.Second

	srv, err := ListenXHTTP("127.0.0.1:0", srvDev, ka, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.xhttpHandler)
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	go srv.Run()
	t.Cleanup(func() { ts.Close(); srv.Close() })

	cli, err := DialXHTTP(ts.Listener.Addr().String(), cliDev, ka, false, true, psk, cipher, "", "/", true, nil, "grpc")
	if err != nil {
		t.Fatalf("DialXHTTP: %v", err)
	}
	cli.xhTLS = &tls.Config{InsecureSkipVerify: true}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	time.Sleep(600 * time.Millisecond)
	xhttpInject(t, cliCtrl, srvCtrl)
}

// TestXHTTPServerH2C verifies the xhttp server accepts an HTTP/2 cleartext (h2c) connection — the
// leg a CDN uses to reach the origin for gRPC. A prior-knowledge h2c client sends a probe (bad
// sid) and must get an HTTP/2 404 back, proving h2c is served on the plain listener.
func TestXHTTPServerH2C(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "h2csrv")
	srv, err := ListenXHTTP("127.0.0.1:0", srvDev, time.Second, false, true, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(150 * time.Millisecond)

	hc := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true, // permit http:// (cleartext) with prior-knowledge h2c
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr) // plaintext, no TLS
		},
	}}
	resp, err := hc.Get("http://" + srv.ln.Addr().String() + "/?s=notavalidsessionid")
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 (h2c), got %s", resp.Proto)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for a bad sid, got %d", resp.StatusCode)
	}
}

// TestSourceIPBind proves the client dialer binds its outbound socket to the configured source
// IP: a server on 127.0.0.1 must see the connection arrive FROM 127.0.0.2 (a loopback alias),
// not from 127.0.0.1. This is what pins egress to a node's own IP on a multi-IP host.
func TestSourceIPBind(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			seen <- "accept-err"
			return
		}
		seen <- c.RemoteAddr().(*net.TCPAddr).IP.String()
		c.Close()
	}()
	b := &TCP{bindIP: "127.0.0.2"}
	c, err := b.dialer(2 * time.Second).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial with bound source: %v", err)
	}
	defer c.Close()
	select {
	case src := <-seen:
		if src != "127.0.0.2" {
			t.Fatalf("server saw source %s, want 127.0.0.2 (bind not applied)", src)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no connection observed")
	}
}

func TestXHTTPConnReadDeadline(t *testing.T) {
	pr, _ := io.Pipe()
	c := &xhttpConn{r: pr, w: io.Discard}
	c.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	start := time.Now()
	buf := make([]byte, 8)
	_, err := c.Read(buf) // pipe never fed; the idle timer must close it and unblock
	if err == nil {
		t.Fatal("expected read error after deadline")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("deadline took too long: %v", d)
	}
}
