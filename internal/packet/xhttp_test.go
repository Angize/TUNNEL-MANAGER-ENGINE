package packet

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// echoXHTTP is a minimal server mirroring the real GET(down)+POST(up) correlation:
// whatever the client POSTs (upstream) is streamed back on its GET (downstream).
func echoXHTTP() *httptest.Server {
	var mu sync.Mutex
	type pipe struct{ pr *io.PipeReader; pw *io.PipeWriter }
	pipes := map[string]*pipe{}
	get := func(sid string) *pipe {
		mu.Lock()
		defer mu.Unlock()
		if p := pipes[sid]; p != nil {
			return p
		}
		pr, pw := io.Pipe()
		p := &pipe{pr, pw}
		pipes[sid] = p
		return p
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sid := r.URL.Query().Get("s")
		p := get(sid)
		if r.Method == http.MethodPost {
			io.Copy(p.pw, r.Body)
			p.pw.Close()
			return
		}
		fl := w.(http.Flusher)
		w.WriteHeader(200)
		fl.Flush()
		buf := make([]byte, 4096)
		for {
			n, e := p.pr.Read(buf)
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

	// write several framed-ish chunks upstream; expect them echoed on the downstream.
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
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
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
	t.Logf("xhttp carrier round-tripped %d bytes both ways", len(got))
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
