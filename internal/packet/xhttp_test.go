package packet

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
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
	b := &BipTCP{addr: srv.Listener.Addr().String(), wsPath: "/", wsTLS: false}
	conn, _, err := b.establishXHTTP()
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
// for xhttp): the client speaks bip frames directly over the GET/POST pair, so a WS handshake
// there misreads the bip handshake as an HTTP request and the tunnel connects but passes no data.
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

// TestTunnelXHTTPStreamOne runs a full tunnel in stream-one mode: a single full-duplex request
// over an HTTP/2 TLS edge (a stand-in for the CDN). The server's handler is served by an h2
// httptest server so the client negotiates h2 and upstream frames flush per-write; its own plain
// listener is idle. Proves stream-one round-trips both ways over one request.
func TestTunnelXHTTPStreamOne(t *testing.T) {
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
