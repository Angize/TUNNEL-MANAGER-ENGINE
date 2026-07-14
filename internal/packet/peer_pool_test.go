package packet

import (
	"encoding/json"
	"net"
	"os"
	"testing"
)

func TestPeerPoolRotateCycles(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	if p.current() != "a" {
		t.Fatalf("first current = %q, want a", p.current())
	}
	got := []string{}
	for i := 0; i < 4; i++ {
		a, moved := p.rotateOnce()
		if !moved {
			t.Fatal("rotateOnce should move in a 3-endpoint pool")
		}
		got = append(got, a)
	}
	// a -> b, c, a, b (proactive, no burns)
	want := []string{"b", "c", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rotation order = %v, want %v", got, want)
		}
	}
}

func TestPeerPoolBurnSkipsAndAdvances(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	// active is a; a fails -> burned, advance to b
	if a, moved := p.fail(); a != "b" || !moved {
		t.Fatalf("after burning a, got %q moved=%v, want b true", a, moved)
	}
	// b fails -> burned, advance to c (a still burned, skipped)
	if a, _ := p.fail(); a != "c" {
		t.Fatalf("after burning b, got %q, want c", a)
	}
	// proactive rotate should now skip the two burned (a,b) and stay on c
	if a, moved := p.rotateOnce(); a != "c" || moved {
		t.Fatalf("only c is live: got %q moved=%v, want c false", a, moved)
	}
}

func TestPeerPoolNeverDeadEndsWhenAllBurned(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.fail() // burn a -> advance to b
	// Burning the last live endpoint must still MOVE (never dead-end, never re-stick on the endpoint we
	// just failed). Unlike the old revive-all, the burns are KEPT (suspect, on backoff) — the pool falls
	// back to the least-bad OTHER endpoint so the tunnel keeps trying while the retests work.
	a, moved := p.fail() // burn b -> advance off b back to a (a is the least-bad other)
	if !moved || a != "a" {
		t.Fatalf("after all-burned: got %q moved=%v, want a true (advance off the failed endpoint)", a, moved)
	}
	p.mu.Lock()
	na, nb := p.health["a"] != nil, p.health["b"] != nil
	p.mu.Unlock()
	if !na || !nb {
		t.Fatalf("both endpoints should stay burned (suspect) after all-burned, got a=%v b=%v", na, nb)
	}
}

func TestPeerPoolAutoBurnOffJustRotates(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, false, 0, "") // auto-burn OFF
	p.fail()
	p.mu.Lock()
	nb := len(p.health)
	p.mu.Unlock()
	if nb != 0 {
		t.Fatalf("auto-burn off must not burn, got %d burned", nb)
	}
}

func TestPeerPoolSucceededClearsBurn(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	p.fail() // burn a, now on b
	// pretend we later rotate back onto a and it works
	p.mu.Lock()
	p.cur = 0 // force active = a (still burned)
	p.mu.Unlock()
	if healed := p.succeeded(); healed != "a" {
		t.Fatalf("succeeded() must return the recovered addr %q, got %q", "a", healed)
	}
	p.mu.Lock()
	burnedA := p.health["a"] != nil
	p.mu.Unlock()
	if burnedA {
		t.Fatal("succeeded() must clear the active endpoint's burn")
	}
	// A second success on the now-healthy endpoint is a no-op — returns "" so no duplicate heal event.
	if healed := p.succeeded(); healed != "" {
		t.Fatalf("succeeded() on a healthy endpoint must return \"\", got %q", healed)
	}
}

// TestPeerPoolSuspectToDeadBackoff walks a single endpoint through the whole health FSM: a fresh failure
// makes it suspect (+30s), each failed live retest steps the backoff, and running off the end drops it to
// dead on the slow interval — exactly the ws edge pool's schedule.
func TestPeerPoolSuspectToDeadBackoff(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	// a fails -> suspect, nextRetest = now + suspectBackoff[0]
	p.fail()
	rec := p.health["a"]
	if rec == nil || rec.state != stateSuspect || rec.fails != 0 || rec.nextRetest != clk+suspectBackoff[0] {
		t.Fatalf("first fail should make a suspect at +%ds, got %+v", suspectBackoff[0], rec)
	}
	// Walk every backoff step by re-failing a due retry; after len(suspectBackoff) failures it is dead.
	for i := 1; i < len(suspectBackoff); i++ {
		clk = rec.nextRetest // make a due
		p.mu.Lock()
		p.cur = 0 // pretend the live retry landed back on a
		p.mu.Unlock()
		p.fail()
		if rec.state != stateSuspect || rec.fails != i {
			t.Fatalf("after %d retest fails a should be suspect fails=%d, got %+v", i, i, rec)
		}
	}
	clk = rec.nextRetest
	p.mu.Lock()
	p.cur = 0
	p.mu.Unlock()
	p.fail() // the final failed retest drops it to dead
	if rec.state != stateDead || rec.nextRetest != clk+deadRetest {
		t.Fatalf("running off the backoff should mark a dead at +%ds, got %+v", deadRetest, rec)
	}
}

// TestPeerPoolDueEndpointReadmitted checks the "data plane is the probe" recovery: a burned endpoint is
// skipped by current() while its backoff is pending, then re-admitted for a live retry once it is due.
func TestPeerPoolDueEndpointReadmitted(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	p.fail() // burn a (suspect), now on b
	if got := p.current(); got != "b" {
		t.Fatalf("while a is suspect current should stay on the healthy b, got %q", got)
	}
	// Burn b too so nothing is healthy; a is still pending (not due) -> current falls back to least-bad.
	p.fail()
	// Advance the clock past a's retest: a becomes DUE and current() must re-admit it for a live retry.
	clk += suspectBackoff[len(suspectBackoff)-1] + deadRetest + 1
	got := p.current()
	if got != "a" && got != "b" {
		t.Fatalf("a due endpoint should be re-admitted, got %q", got)
	}
	// A success on the re-admitted endpoint heals it.
	p.succeeded()
	p.mu.Lock()
	healed := p.health[p.addrs[p.cur]] == nil
	p.mu.Unlock()
	if !healed {
		t.Fatal("succeeded() on a re-admitted endpoint should heal it back to healthy")
	}
}

// TestPeerPoolSelectPin verifies the manual pin: current() forces the pinned endpoint, isPinned holds it,
// a landing (pinApplied) releases it, and an unknown key is rejected.
func TestPeerPoolSelectPin(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	p.now = func() int64 { return clk }
	if p.selectEntry("zzz") {
		t.Fatal("selectEntry must reject an unknown key")
	}
	if !p.selectEntry("c") {
		t.Fatal("selectEntry should find c")
	}
	if !p.isPinned() {
		t.Fatal("pool should report pinned right after selectEntry")
	}
	if got := p.current(); got != "c" {
		t.Fatalf("current() must force the pinned c, got %q", got)
	}
	// A fail() racing the pin must NOT burn or move off the pinned endpoint (atomic guard under p.mu):
	// current() keeps forcing c until it lands or the TTL lapses.
	if a, moved := p.fail(); a != "c" || moved {
		t.Fatalf("fail() while pinned must stay on c: got %q moved=%v, want c false", a, moved)
	}
	p.mu.Lock()
	burnedC := p.health["c"] != nil
	p.mu.Unlock()
	if burnedC {
		t.Fatal("fail() while pinned must not burn the pinned endpoint")
	}
	if a, moved := p.rotateOnce(); a != "c" || moved {
		t.Fatalf("rotateOnce() while pinned must stay on c: got %q moved=%v, want c false", a, moved)
	}
	p.pinApplied("c") // the carrier landed on c -> pin releases
	if p.isPinned() {
		t.Fatal("pinApplied on the pinned endpoint must release the pin")
	}
	// After the TTL a stale pin self-releases even without a land.
	p.selectEntry("a")
	clk += pinTTL + 1
	if p.isPinned() {
		t.Fatal("a pin past its TTL must self-release")
	}
}

// TestPeerPoolProbeAllNow checks that probe-now pulls every burned endpoint's retest forward so it is
// immediately due.
func TestPeerPoolProbeAllNow(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	p.fail() // burn a, +30s
	if r := p.health["a"]; r == nil || r.nextRetest <= clk {
		t.Fatalf("a should be burned with a future retest, got %+v", r)
	}
	p.probeAllNow()
	if r := p.health["a"]; r == nil || r.nextRetest != clk {
		t.Fatalf("probeAllNow should pull a's retest to now, got %+v", r)
	}
}

// TestPeerPoolStatusFileFSM checks the richer status file: active, the health array with per-endpoint
// state, the flat burned list, and the pin all round-trip through the JSON the panel reads.
func TestPeerPoolStatusFileFSM(t *testing.T) {
	dir := t.TempDir()
	sp := dir + "/core-x.peerpool"
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, sp)
	p.fail()           // burn a, active -> b
	p.selectEntry("c") // pin c
	data, err := os.ReadFile(sp)
	if err != nil {
		t.Fatalf("status file not written: %v", err)
	}
	var st struct {
		Active string   `json:"active"`
		Addrs  []string `json:"addrs"`
		Burned []string `json:"burned"`
		Pin    string   `json:"pin"`
		Health []struct {
			Key, State string
		} `json:"health"`
	}
	if json.Unmarshal(data, &st) != nil {
		t.Fatalf("status file is not valid JSON: %s", data)
	}
	if st.Active != "c" || st.Pin != "c" {
		t.Fatalf("after pinning c: active=%q pin=%q, want c/c", st.Active, st.Pin)
	}
	if len(st.Addrs) != 3 || len(st.Health) != 3 {
		t.Fatalf("status should list all 3 endpoints, got addrs=%v health=%d", st.Addrs, len(st.Health))
	}
	// a was burned; pinning c cleared c's (never-set) mark. Exactly a should be suspect in the health map.
	suspect := map[string]bool{}
	for _, h := range st.Health {
		if h.State == stateSuspect {
			suspect[h.Key] = true
		}
	}
	if !suspect["a"] {
		t.Fatalf("a should be reported suspect in health, got %v", suspect)
	}
}

func TestPeerPoolSingleEndpointNoop(t *testing.T) {
	p := NewPeerPool([]string{"only"}, true, 0, "")
	if a, moved := p.fail(); a != "only" || moved {
		t.Fatalf("single-endpoint fail = %q moved=%v, want only false", a, moved)
	}
	if a, moved := p.rotateOnce(); a != "only" || moved {
		t.Fatalf("single-endpoint rotate = %q moved=%v, want only false", a, moved)
	}
}

// TestTCPDialTargetUsesPool verifies the TCP integration points without a real dial: dialTarget
// reads the pool's current endpoint when a pool is wired and falls back to the fixed peer otherwise,
// and a ws client refuses the pool (the ws edge pool owns rotation there).
func TestTCPDialTargetUsesPool(t *testing.T) {
	b := &TCP{isClient: true, addr: "1.1.1.1:9000"}
	if got := b.dialTarget(); got != "1.1.1.1:9000" {
		t.Fatalf("no pool: dialTarget = %q, want the fixed peer", got)
	}
	b.SetPeerPool(NewPeerPool([]string{"2.2.2.2:9000", "3.3.3.3:9000"}, true, 0, ""))
	if b.pp == nil {
		t.Fatal("direct-tcp client should accept a peer pool")
	}
	if got := b.dialTarget(); got != "2.2.2.2:9000" {
		t.Fatalf("with pool: dialTarget = %q, want the pool's current endpoint", got)
	}
	// After burning the current endpoint the next dial must target the advanced one.
	b.pp.fail()
	if got := b.dialTarget(); got != "3.3.3.3:9000" {
		t.Fatalf("after burn: dialTarget = %q, want the next endpoint", got)
	}

	// A ws client must NOT accept a peer pool — ws has its own edge pool.
	w := &TCP{isClient: true, ws: true, addr: "1.1.1.1:443"}
	w.SetPeerPool(NewPeerPool([]string{"2.2.2.2:443", "3.3.3.3:443"}, true, 0, ""))
	if w.pp != nil {
		t.Fatal("ws client must reject a peer pool")
	}
	if got := w.dialTarget(); got != "1.1.1.1:443" {
		t.Fatalf("ws client: dialTarget = %q, want the fixed addr", got)
	}
}

func TestTCPSourceIPUsesPool(t *testing.T) {
	b := &TCP{isClient: true, bindIP: "10.0.0.1"}
	if got := b.sourceIP(); got != "10.0.0.1" {
		t.Fatalf("no source pool: sourceIP = %q, want the fixed bindIP", got)
	}
	b.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, true, 0, ""))
	if b.sp == nil {
		t.Fatal("direct-tcp client should accept a source pool")
	}
	if got := b.sourceIP(); got != "10.0.0.5" {
		t.Fatalf("with source pool: sourceIP = %q, want the pool's current", got)
	}
	if !b.rotateSourceTCP(true) { // proactive rotate should move in a 2-entry pool
		t.Fatal("rotateSourceTCP should report moved=true")
	}
	if got := b.sourceIP(); got != "10.0.0.6" {
		t.Fatalf("after rotate: sourceIP = %q, want the advanced source", got)
	}
	// ws client must refuse a source pool (its edge pool owns rotation).
	w := &TCP{isClient: true, ws: true, bindIP: "10.0.0.1"}
	w.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, true, 0, ""))
	if w.sp != nil {
		t.Fatal("ws client must reject a source pool")
	}
}

// TestUDPSourceRebindSwapsConn checks the udp source-rotation mechanics: rotateSourceUDP opens a fresh
// socket on the new source IP, swaps it in, and bumps rebindGen so the receive loop knows the old
// socket's imminent read error is a deliberate swap (not a death). Uses loopback (127.0.0.0/8).
func TestUDPSourceRebindSwapsConn(t *testing.T) {
	c0, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("initial ListenUDP: %v", err)
	}
	b := &UDP{isClient: true}
	b.conn.Store(c0)
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, true, 0, ""))
	gen0 := b.rebindGen.Load()

	b.rotateSourceUDP(true) // advance 127.0.0.1 -> 127.0.0.2 and rebind
	if b.rebindGen.Load() == gen0 {
		t.Fatal("rebindGen must advance on a source rebind so netToTun keeps the loop alive")
	}
	nc := b.conn.Load()
	if nc == c0 {
		t.Fatal("conn was not swapped")
	}
	if got := nc.LocalAddr().(*net.UDPAddr).IP; !got.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("rebound socket source = %v, want 127.0.0.2", got)
	}
	nc.Close() // c0 was already closed by rotateSourceUDP
}

// TestUDPSourcePoolBindsInitialSource checks that wiring a source pool rebinds the socket to SrcIPs[0]
// at setup, so the client egresses from the pool's first source immediately (not the OS default until
// the first rotation — which on a failover-only pool never happens).
func TestUDPSourcePoolBindsInitialSource(t *testing.T) {
	c0, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("initial ListenUDP: %v", err)
	}
	b := &UDP{isClient: true}
	b.conn.Store(c0)
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.2", "127.0.0.3"}, true, 0, "")) // first entry != initial bind
	got := b.conn.Load().LocalAddr().(*net.UDPAddr).IP
	if !got.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("SetSourcePool should bind the initial source to SrcIPs[0]=127.0.0.2, got %v", got)
	}
	b.conn.Load().Close()
}

// TestRotationControllerCouplesSource verifies the failover policy: burning destinations advances the
// source only once every destination has been tried against the current source.
func TestRotationControllerCouplesSource(t *testing.T) {
	dst := NewPeerPool([]string{"d0", "d1"}, true, 0, "") // size 2
	src := NewPeerPool([]string{"s0", "s1"}, true, 0, "")
	rc := newRotationController(dst, src)
	dstMoves, srcMoves := 0, 0
	rotDst := func(bool) { dstMoves++ }
	rotSrc := func(bool) { srcMoves++ }

	rc.fail(rotDst, rotSrc) // destRot 1
	if dstMoves != 1 || srcMoves != 0 {
		t.Fatalf("after 1 fail: dst=%d src=%d, want 1/0", dstMoves, srcMoves)
	}
	rc.fail(rotDst, rotSrc) // destRot 2 == size -> source advances, reset
	if dstMoves != 2 || srcMoves != 1 {
		t.Fatalf("after 2 fails: dst=%d src=%d, want 2/1 (source walked)", dstMoves, srcMoves)
	}
	rc.success() // clears the dest-cycle counter
	rc.fail(rotDst, rotSrc)
	if srcMoves != 1 {
		t.Fatalf("success() must reset destRot so the source doesn't advance early, got src=%d", srcMoves)
	}

	// Source-only pool (no destination pool) advances the source on every failure.
	rc2 := newRotationController(nil, NewPeerPool([]string{"s0", "s1"}, true, 0, ""))
	n := 0
	rc2.fail(func(bool) { t.Fatal("no dest pool: rotDst must not be called") }, func(bool) { n++ })
	if n != 1 {
		t.Fatalf("source-only fail should advance the source once, got %d", n)
	}
}

// TestRotationControllerPinAutoReleasesOnProvenBlock checks R1: a manual pin on an endpoint that stays
// blocked auto-releases after pinFailRelease proven-dead rounds so the tunnel recovers instead of freezing
// on it for the whole pinTTL — and a success in between resets the count so a real transient never
// releases a good pin.
func TestRotationControllerPinAutoReleasesOnProvenBlock(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"d0", "d1"}, true, 0, "")
	dst.now = func() int64 { return clk }
	rc := newRotationController(dst, nil)
	if !dst.selectEntry("d1") {
		t.Fatal("selectEntry d1 failed")
	}
	moves := 0
	rotDst := func(bool) { moves++ }
	rotSrc := func(bool) {}

	// The rounds before the release threshold are absorbed: the pin holds and no failover happens.
	for i := 0; i < pinFailRelease-1; i++ {
		rc.fail(rotDst, rotSrc)
		if !dst.isPinned() {
			t.Fatalf("pin must survive proven-dead round %d (< pinFailRelease)", i)
		}
		if moves != 0 {
			t.Fatalf("no failover while the pin is held, got moves=%d", moves)
		}
	}
	// A live success resets the counter AND lands (clears) the pin. Re-pin and confirm the release count
	// restarts from zero — accumulated rounds from a prior pin must never leak into a fresh one.
	rc.success()
	if dst.isPinned() {
		t.Fatal("success() lands the pin, so it must clear it")
	}
	if !dst.selectEntry("d1") {
		t.Fatal("re-pin d1 failed")
	}
	moves = 0
	for i := 0; i < pinFailRelease-1; i++ {
		rc.fail(rotDst, rotSrc)
		if !dst.isPinned() {
			t.Fatalf("the count must restart after success; the re-pin must survive round %d", i)
		}
		if moves != 0 {
			t.Fatalf("no failover while the re-pin is held, got moves=%d", moves)
		}
	}
	// The pinFailRelease-th consecutive proven-dead round releases the pin AND fails over in the same call.
	rc.fail(rotDst, rotSrc)
	if dst.isPinned() {
		t.Fatal("a pin on a proven-blocked endpoint must auto-release at pinFailRelease")
	}
	if moves != 1 {
		t.Fatalf("the releasing round must also fail over off the blocked endpoint, got moves=%d", moves)
	}
}

// TestPeerPoolExpirePinFlushesStatus checks P1: when a pin's TTL lapses, the status file the panel reads
// is flushed so it stops showing a pin the dataplane no longer honours.
func TestPeerPoolExpirePinFlushesStatus(t *testing.T) {
	dir := t.TempDir()
	sp := dir + "/core-x.peerpool"
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, sp)
	p.now = func() int64 { return clk }
	p.selectEntry("b") // pins b and writes the status file with pin=b
	readPin := func() string {
		data, err := os.ReadFile(sp)
		if err != nil {
			t.Fatalf("status read: %v", err)
		}
		var st struct {
			Pin string `json:"pin"`
		}
		if err := json.Unmarshal(data, &st); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return st.Pin
	}
	if readPin() != "b" {
		t.Fatalf("status should show pinned b, got %q", readPin())
	}
	p.expirePinIfLapsed() // still within TTL -> no change
	if readPin() != "b" {
		t.Fatalf("pin within its TTL must stay in the status file, got %q", readPin())
	}
	clk += pinTTL + 1 // TTL lapses
	p.expirePinIfLapsed()
	if readPin() != "" {
		t.Fatalf("status must clear the pin once its TTL lapses, got %q", readPin())
	}
}
