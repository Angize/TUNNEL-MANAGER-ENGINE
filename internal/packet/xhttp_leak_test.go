package packet

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// settleGoroutines waits for the runtime to reach a steady goroutine count: it GCs and polls until
// the number stops falling (async teardown — an h2 conn's reader/writer exit only after the conn is
// closed) or a short budget elapses, then returns the last reading.
func settleGoroutines() int {
	prev := runtime.NumGoroutine()
	for i := 0; i < 40; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n >= prev { // stopped falling — settled
			return n
		}
		prev = n
	}
	return prev
}

// TestXHTTPGrpcNoConnLeakOnRotation guards the grpc teardown path: establishing and retiring many
// grpc sessions (the proactive-rotation churn) must not grow the process goroutine count. It backs
// the force-close-on-teardown fix in dialXHTTPOnce, where a retired session's underlying h2 conn was
// closed only via CloseIdleConnections — which, on a fresh-per-session transport with no
// IdleConnTimeout, can race the async stream teardown and, if the far side holds the TCP conn open
// (a CDN edge does), never actually close it, leaking the conn's reader/writer goroutines and fd
// until a new standby dial can no longer be made and rotation silently stalls.
//
// NOTE ON TEETH: a loopback httptest h2 server tears the conn down promptly on stream-cancel, so this
// in-process test does NOT reproduce the CDN-latency-dependent leak — it passes with and without the
// fix. It is a no-regression guard (the teardown path reaps its own goroutines) and executable
// documentation of the concern, NOT proof the production stall is resolved. Production confirmation
// comes from the goroutine-count heartbeat (diagLoop) and the rotation-skip logs added alongside.
func TestXHTTPGrpcNoConnLeakOnRotation(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "xhgleak")
	srv, err := ListenXHTTP("127.0.0.1:0", srvDev, time.Second, false, true, psk, "aes-256-gcm")
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

	b := &TCP{addr: ts.Listener.Addr().String(), ws: true, xhttp: true, xhMode: "grpc",
		wsPath: "/", wsTLS: true, xhTLS: &tls.Config{InsecureSkipVerify: true}}

	establishAndRetire := func() {
		conn, _, _, err := b.establishXHTTP()
		if err != nil {
			t.Fatalf("establishXHTTP: %v", err)
		}
		_, _ = conn.Write([]byte("prime")) // make the h2 conn fully live before we retire it
		conn.Close()                        // the rotation teardown path: closeFn -> closeIdle -> forceClose
	}

	// Warm up so the http2 package's steady-state goroutines are already spun up before we baseline.
	for i := 0; i < 5; i++ {
		establishAndRetire()
	}
	base := settleGoroutines()

	const rotations = 60
	for i := 0; i < rotations; i++ {
		establishAndRetire()
	}
	after := settleGoroutines()

	if after > base+15 {
		t.Fatalf("goroutine leak across %d grpc rotations: base=%d after=%d (want <= base+15) — retired h2 conns not reaped",
			rotations, base, after)
	}
	t.Logf("grpc rotation leak check: base=%d after=%d across %d rotations", base, after, rotations)
}
