package packet

import (
	"io"
	"net/http"
	"net/http/httptest"
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
