package packet

import (
	"bytes"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newWarmSoakClient spins up a real in-process ListenWS server and a warm-standby pooled client
// (one edge IP, two SNIs fronting it) with a given proactive-rotation interval, so the make-before-
// break machinery is exercised hard. Returns the client, the pool, and both TUN control ends.
func newWarmSoakClient(t *testing.T, rotate time.Duration) (*TCP, *wsPool, *os.File, *os.File) {
	t.Helper()
	const psk = "rotation-soak-psk-abcdefghijklmnop"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "soaksrv")
	cliDev, cliCtrl := tunPair(t, "soakcli")
	ka := time.Second
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, ka, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	pool := newWSPool([]string{addr}, snis("front-a", "front-b"), true, "")
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: cipher, keepalive: ka, psk: psk,
		ws: true, wsTLS: false, pool: pool, warmStandby: true, rotate: rotate,
		idle: idleFor(ka), isClient: true, addr: "pool", closeCh: make(chan struct{})}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	waitFor(t, 5*time.Second, "active up", func() bool { return cli.cur.Load() != nil })
	return cli, pool, cliCtrl, srvCtrl
}

// drainCounter runs a single background reader that counts packets arriving on ctrl. The TUN control
// end is a socketpair os.File that does NOT honor SetReadDeadline, so we must never block-read it on
// the test goroutine; one background reader (unblocked when ctrl closes on cleanup) is the safe shape.
func drainCounter(ctrl *os.File, n *int64) {
	go func() {
		buf := make([]byte, 2048)
		for {
			m, err := ctrl.Read(buf)
			if m > 0 {
				atomic.AddInt64(n, 1)
			}
			if err != nil {
				return
			}
		}
	}()
}

// TestRotationSoakRapidRotate proves proactive rotation KEEPS PROGRESSING under a fast rotate
// interval — it never wedges on one edge — while the tunnel keeps carrying data. If the make-before-
// break loop froze, the active would stay pinned to one combo and the distinct-active assertion fails.
func TestRotationSoakRapidRotate(t *testing.T) {
	cli, pool, cliCtrl, srvCtrl := newWarmSoakClient(t, 150*time.Millisecond)

	var delivered int64
	drainCounter(srvCtrl, &delivered)

	seen := map[string]int{}
	var mu sync.Mutex
	stop := make(chan struct{})
	go func() { // sample the live active edge; a frozen rotation shows only ONE value
		tk := time.NewTicker(25 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				if a := poolActive(pool); a != "" {
					mu.Lock()
					seen[a]++
					mu.Unlock()
				}
			}
		}
	}()

	pkt := bytes.Repeat([]byte{0x7E}, 160)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := cliCtrl.Write(pkt); err != nil {
			t.Fatalf("client write: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)

	mu.Lock()
	distinct := len(seen)
	mu.Unlock()
	if distinct < 2 {
		t.Fatalf("rotation appears frozen: saw only %d distinct active edge(s) across 3s of 150ms rotation (want >= 2): %v", distinct, seen)
	}
	if cli.cur.Load() == nil {
		t.Fatal("tunnel has no active carrier after the rapid-rotate soak")
	}
	if got := atomic.LoadInt64(&delivered); got == 0 {
		t.Fatal("no data traversed the tunnel during rapid rotation — the tunnel was dead throughout")
	}
	t.Logf("rapid-rotate soak: %d distinct active edges, %d packets delivered through the churn: %v",
		distinct, atomic.LoadInt64(&delivered), seen)
}

// TestRotationSoakPinStorm hammers the manual-pin path: it alternates the pinned SNI as fast as the
// loop can service it. It proves a burst of operator pins never deadlocks the warm loop or strands
// the tunnel — the manual-switch / re-dial / rebuild branch stays live, and data still flows.
func TestRotationSoakPinStorm(t *testing.T) {
	cli, _, cliCtrl, srvCtrl := newWarmSoakClient(t, 0) // rotation off: isolate the pin path
	waitFor(t, 5*time.Second, "warm standby up", func() bool { return cli.standby.Load() != nil })

	var delivered int64
	drainCounter(srvCtrl, &delivered)

	stop := make(chan struct{})
	go func() {
		targets := []string{"front-a", "front-b"}
		i := 0
		tk := time.NewTicker(60 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				cli.SelectEdge("sni", targets[i%2])
				i++
			}
		}
	}()

	pkt := bytes.Repeat([]byte{0x5C}, 140)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := cliCtrl.Write(pkt); err != nil {
			t.Fatalf("client write during pin storm: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)

	// The tunnel must still be live after the storm, and data must have flowed through it.
	waitFor(t, 5*time.Second, "active still up after pin storm", func() bool { return cli.cur.Load() != nil })
	if got := atomic.LoadInt64(&delivered); got == 0 {
		t.Fatal("no data traversed the tunnel during the pin storm")
	}
	t.Logf("pin-storm soak: survived, %d packets delivered through the storm", atomic.LoadInt64(&delivered))
}

// TestRotationSoakFailoverStorm repeatedly kills the active carrier and asserts the loop recovers
// each time (a carrier comes back and data resumes), for many cycles. It stresses the promote ->
// requestStandby -> dialActiveAsync recovery machinery under repeated failure — the path that, if it
// leaked standbyBuilding or dropped the rebuild, would eventually stop recovering.
func TestRotationSoakFailoverStorm(t *testing.T) {
	cli, _, cliCtrl, srvCtrl := newWarmSoakClient(t, 0)

	var delivered int64
	drainCounter(srvCtrl, &delivered)

	pkt := bytes.Repeat([]byte{0x93}, 150)
	for cycle := 0; cycle < 15; cycle++ {
		if a := cli.cur.Load(); a != nil {
			a.conn.Close() // kill the active carrier
		}
		// The loop must bring a carrier back (promote the standby, or dial a fresh active)...
		waitFor(t, 6*time.Second, "carrier recovered after kill", func() bool { return cli.cur.Load() != nil })
		// ...and data must resume over it. Write until the delivered counter advances.
		before := atomic.LoadInt64(&delivered)
		resumed := false
		for try := 0; try < 60 && !resumed; try++ {
			if _, err := cliCtrl.Write(pkt); err != nil {
				t.Fatalf("cycle %d: client write: %v", cycle, err)
			}
			if atomic.LoadInt64(&delivered) > before {
				resumed = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !resumed {
			t.Fatalf("cycle %d: tunnel did not resume data flow within 3s after failover", cycle)
		}
	}
	t.Logf("failover-storm soak: survived 15 active-carrier kills with data recovery each time (%d pkts)",
		atomic.LoadInt64(&delivered))
}
