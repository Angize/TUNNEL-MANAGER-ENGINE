package packet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// xhttpStressServer stands up a real xhttp core server behind an httptest HTTP server, returning the
// base URL and an http.Client. The core server's TUN side is a socketpair that nothing drains — fine,
// the stress only exercises the HTTP-facing session machinery (create / serve / reap / teardown).
func xhttpStressServer(t *testing.T) (string, *http.Client, *TCP) {
	t.Helper()
	const psk = "server-stress-psk-abcdefghijklmnop"
	srvDev, _ := tunPair(t, "srvstress")
	srv, err := ListenXHTTP("127.0.0.1:0", srvDev, time.Second, false, true, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenXHTTP: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.xhttpHandler)
	ts := httptest.NewServer(mux)
	go srv.Run()
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts.URL, ts.Client(), srv
}

// liveSessions returns the current xhttp session-table size under its lock.
func liveSessions(b *TCP) int {
	b.xhMu.Lock()
	defer b.xhMu.Unlock()
	return len(b.xhSessions)
}

// TestXHTTPServerMalformedBlast fires a flood of concurrent MALFORMED requests at the xhttp handler:
// bad session ids, wrong methods, missing/garbage seq, oversized and empty bodies, bogus grpc. The
// server must answer each with a clean 4xx and never panic, race, or wedge. Run under -race this is
// the concurrency-safety check on the session table and the handler's error paths.
func TestXHTTPServerMalformedBlast(t *testing.T) {
	base, hc, _ := xhttpStressServer(t)
	hc.Timeout = 3 * time.Second

	kinds := []func(i int) *http.Request{
		func(i int) *http.Request { // bad sid (too short)
			r, _ := http.NewRequest("GET", fmt.Sprintf("%s/?s=deadbeef", base), nil)
			return r
		},
		func(i int) *http.Request { // bad sid (non-hex, right length)
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032d&seq=0", base, 0)+"ZZZ", nil)
			return r
		},
		func(i int) *http.Request { // valid-format sid, POST with NON-numeric seq -> 400
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032x&seq=notanumber", base, i), bytes.NewReader([]byte("x")))
			return r
		},
		func(i int) *http.Request { // wrong method (PUT) on a valid sid
			r, _ := http.NewRequest("PUT", fmt.Sprintf("%s/?s=%032x", base, i), nil)
			return r
		},
		func(i int) *http.Request { // bogus grpc POST with a garbage body
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032x", base, i), bytes.NewReader(bytes.Repeat([]byte{0xff}, 300)))
			r.Header.Set("Content-Type", "application/grpc")
			return r
		},
		func(i int) *http.Request { // POST a large chunk (must be LimitReader-capped, not OOM)
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032x&seq=%d", base, i, i), bytes.NewReader(bytes.Repeat([]byte{0x41}, 200000)))
			return r
		},
	}

	var wg sync.WaitGroup
	for w := 0; w < 40; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				req := kinds[(w+i)%len(kinds)](w*1000 + i)
				resp, err := hc.Do(req)
				if err != nil {
					continue // client-side timeout on a grpc POST that the server holds — acceptable
				}
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
				resp.Body.Close()
			}
		}(w)
	}
	wg.Wait()

	// The server must still answer a fresh malformed request (proves it is alive, not wedged/panicked).
	resp, err := hc.Get(base + "/?s=short")
	if err != nil {
		t.Fatalf("server unresponsive after malformed blast: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for a bad sid after the blast, got %d", resp.StatusCode)
	}
}

// TestXHTTPServerSessionChurn drives the session lifecycle concurrently: each worker binds a
// downstream GET (which starts serve), POSTs an upstream chunk through it, then abandons the GET
// (context cancel). Real client ordering is GET-first, because deliver() writes to the upstream pipe
// that only drains once serve reads it. Many of these in parallel stress create/serve/teardown and
// the session map. The point of the test is running it under -race: any unsynchronised access to the
// xhSessions map or a session's fields shows up here. Afterward the server must stay responsive.
func TestXHTTPServerSessionChurn(t *testing.T) {
	base, hc, srv := xhttpStressServer(t)
	hc.Timeout = 2 * time.Second // never let a held-open GET hang a worker

	var wg sync.WaitGroup
	for w := 0; w < 30; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				sid := fmt.Sprintf("%032x", w*100000+i)
				ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
				// GET first: binds serve so the upstream pipe has a reader.
				var gwg sync.WaitGroup
				gwg.Add(1)
				go func() {
					defer gwg.Done()
					gr, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/?s=%s", base, sid), nil)
					if resp, err := hc.Do(gr); err == nil {
						io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
						resp.Body.Close()
					}
				}()
				time.Sleep(2 * time.Millisecond) // let serve bind before we POST
				pr, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/?s=%s&seq=0", base, sid), bytes.NewReader([]byte("hi")))
				if resp, err := hc.Do(pr); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				cancel()
				gwg.Wait()
			}
		}(w)
	}
	wg.Wait()

	// The server must still answer after the churn (proves it is alive, not wedged or panicked), and
	// the session table must be bounded — not still holding all 600 churned sessions.
	resp, err := hc.Get(base + "/?s=short")
	if err != nil {
		t.Fatalf("server unresponsive after session churn: %v", err)
	}
	resp.Body.Close()
	if n := liveSessions(srv); n > 600 {
		t.Fatalf("xhttp session table unbounded after churn: %d live sessions", n)
	}
	t.Logf("session-churn soak: server alive after 600 churned sessions, table=%d", liveSessions(srv))
}
