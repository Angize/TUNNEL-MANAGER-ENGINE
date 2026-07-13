package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func snis(hosts ...string) []wsSNIEntry {
	out := make([]wsSNIEntry, len(hosts))
	for i, h := range hosts {
		out[i] = wsSNIEntry{host: h, path: "/"}
	}
	return out
}

// clockPool builds a pool with an injectable clock so the FSM's scheduling is deterministic.
// The returned pointer is the "now" value; bump it to advance time.
func clockPool(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) (*wsPool, *int64) {
	p := newWSPool(ips, snis, autoBurn, statusPath)
	var now int64 = 1000
	p.now = func() int64 { return now }
	return p, &now
}

func TestPoolRotatesAllCombos(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		ip, sni, ok := p.current()
		if !ok {
			t.Fatal("pool empty unexpectedly")
		}
		seen[ip+"|"+sni.host] = true
		p.advance()
	}
	for _, want := range []string{"a|x", "a|y", "b|x", "b|y"} {
		if !seen[want] {
			t.Fatalf("combo %s never selected; got %v", want, seen)
		}
	}
}

// updateECH persists a self-healed ECH key onto the matching pool SNI and reports a real change
// exactly once, so the self-heal event fires per rotation (first heal) not per reconnect (repeats).
func TestPoolUpdateECHTransitionGate(t *testing.T) {
	p := newWSPool([]string{"a"}, snis("x", "y"), true, "")
	fresh := []byte{1, 2, 3}
	// first heal on x: stored key (nil) differs -> change reported, key persisted
	if !p.updateECH("x", fresh) {
		t.Fatal("first updateECH should report a change")
	}
	if _, sni, _ := p.current(); string(sni.ech) != string(fresh) {
		t.Fatalf("current() should carry the persisted key, got %v", sni.ech)
	}
	// same key again (next reconnect uses the fresh key, or a concurrent healer) -> no change, no event
	if p.updateECH("x", fresh) {
		t.Fatal("repeat updateECH with an unchanged key must report no change (suppresses repeat events)")
	}
	// a later rotation delivers a different key -> change reported again
	if !p.updateECH("x", []byte{9, 9}) {
		t.Fatal("updateECH with a rotated key should report a change")
	}
	// unknown host -> no change (never panics, never mislabels)
	if p.updateECH("zzz", fresh) {
		t.Fatal("updateECH for an absent host must report no change")
	}
	// the other SNI stays untouched
	if p.snis[1].host != "y" || p.snis[1].ech != nil {
		t.Fatalf("sibling SNI y should be untouched, got %#v", p.snis[1])
	}
}

// A genuine pool down must be balanced by exactly one paired "up"/reconnect on the next
// successful (re)connect, while the initial connect and plain rotations stay silent — so the panel
// never shows an unbalanced "disconnected" for a tunnel that recovered.
func TestPoolDownReconnectPairing(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")

	p.setActive("a · x") // initial connect: no prior down -> silent
	if len(p.events) != 0 {
		t.Fatalf("initial connect must emit no event, got %+v", p.events)
	}

	p.down("reset", "a · x") // genuine drop
	p.setActive("b · x")     // reconnect on a new edge -> paired up
	if len(p.events) != 2 || p.events[0].Kind != "down" || p.events[1].Kind != "up" || p.events[1].Code != "reconnect" {
		t.Fatalf("want down then up/reconnect, got %+v", p.events)
	}

	p.setActive("a · x") // a plain rotation (no pending down) must NOT emit an up
	if len(p.events) != 2 {
		t.Fatalf("rotation without a pending down must be silent, got %d events", len(p.events))
	}

	p.down("throttle", "a · x") // a second drop
	p.setActive("a · x")        // reconnect on the SAME edge still pairs
	if len(p.events) != 4 || p.events[3].Kind != "up" {
		t.Fatalf("a same-edge reconnect after a down must still emit up, got %+v", p.events)
	}
}

// A verdict of IP_GUILTY (applied via markSuspect) moves a healthy IP into suspect, and
// current() then skips it while a healthy alternative remains.
func TestMarkSuspectPullsFromRotation(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "a", "test")
	if r := p.ipHealth["a"]; r == nil || r.state != stateSuspect || r.fails != 0 {
		t.Fatalf("a should be suspect with fails=0, got %#v", r)
	}
	for i := 0; i < 5; i++ {
		ip, _, ok := p.current()
		if !ok || ip != "b" {
			t.Fatalf("suspect a must be skipped while b is healthy; got ip=%q ok=%v", ip, ok)
		}
		p.advance()
	}
}

// The suspect backoff walks 30,60,120,300,600 (as nextRetest deltas) over five failed retests,
// then the entry drops to dead on the sixth failure (the initial markSuspect is failure #1).
func TestSuspectBackoffThenDead(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "a", "test")
	if got := p.ipHealth["a"].nextRetest; got != *now+30 {
		t.Fatalf("entry retest should be now+30, got %d (now=%d)", got, *now)
	}
	wantNext := []int64{60, 120, 300, 600} // deltas after failed retests 1..4
	for i, w := range wantNext {
		p.retestResult("ip", "a", false)
		r := p.ipHealth["a"]
		if r.state != stateSuspect {
			t.Fatalf("retest %d: still suspect expected, got %q", i+1, r.state)
		}
		if r.fails != i+1 {
			t.Fatalf("retest %d: fails=%d, want %d", i+1, r.fails, i+1)
		}
		if r.nextRetest != *now+w {
			t.Fatalf("retest %d: nextRetest=%d, want %d", i+1, r.nextRetest, *now+w)
		}
	}
	// Fifth failed retest (sixth failure overall) -> dead on the slow interval.
	p.retestResult("ip", "a", false)
	r := p.ipHealth["a"]
	if r.state != stateDead || r.nextRetest != *now+deadRetest {
		t.Fatalf("expected dead at now+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest)
	}
	// A dead entry's failed retest stays dead and reschedules on the slow interval from now.
	*now = 5000
	p.retestResult("ip", "a", false)
	if r := p.ipHealth["a"]; r.state != stateDead || r.nextRetest != 5000+deadRetest {
		t.Fatalf("dead entry should stay dead at 5000+%d, got state=%q next=%d", deadRetest, r.state, r.nextRetest)
	}
}

// A successful background retest that heals a sidelined edge must emit a discrete "heal"/"retest"
// event (so the recovery is visible in the panel log), while a FAILED retest must not.
func TestRetestHealEmitsEvent(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "a", "test") // emits a burn event
	base := len(p.events)
	p.retestResult("ip", "a", false) // failed retest — no heal event
	if len(p.events) != base {
		t.Fatalf("a failed retest must not emit an event, got %+v", p.events[base:])
	}
	// Heals "a": emits heal/retest AND — because it restores the 2nd healthy IP of this 2-IP pool —
	// a pool/restored event (rotation can resume). Order: the heal first, then the pool transition.
	p.retestResult("ip", "a", true)
	if len(p.events) != base+2 {
		t.Fatalf("a successful retest that also un-degrades the pool must emit heal + pool/restored, got %+v", p.events[base:])
	}
	if ev := p.events[base]; ev.Kind != "heal" || ev.Code != "retest" || ev.Detail != "ip:a" {
		t.Fatalf("want heal/retest/ip:a, got %+v", ev)
	}
	if ev := p.events[base+1]; ev.Kind != "pool" || ev.Code != "restored" {
		t.Fatalf("want pool/restored once the recovery restored rotation, got %+v", ev)
	}
	// retestResult on a cleared (already-healthy) entry is a no-op — no duplicate heal.
	n := len(p.events)
	p.retestResult("ip", "a", true)
	if len(p.events) != n {
		t.Fatalf("retest on an already-healthy entry must be silent, got %+v", p.events[n:])
	}
}

// ANY successful retest clears the record back to healthy (in rotation again).
func TestSuccessfulRetestHealsToHealthy(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "a", "test")
	p.retestResult("ip", "a", false) // suspect, fails=1
	p.retestResult("ip", "a", true)  // heals
	if p.ipHealth["a"] != nil {
		t.Fatalf("a should be healthy again, got %#v", p.ipHealth["a"])
	}
	// Also proven healthy via a live success on a dead entry.
	p.markSuspect("sni", "x", "test")
	p.ipHealth["a"] = &healthRec{state: stateDead, nextRetest: 9999}
	p.succeeded("a", "x")
	if p.ipHealth["a"] != nil || p.sniHealth["x"] != nil {
		t.Fatalf("succeeded must clear both axes; ip=%#v sni=%#v", p.ipHealth["a"], p.sniHealth["x"])
	}
}

// current() never dead-ends: with nothing fully healthy it returns the least-bad combo —
// suspect preferred over dead, then soonest nextRetest.
func TestCurrentFallbackLeastBad(t *testing.T) {
	p, _ := clockPool([]string{"a", "b"}, snis("x", "y"), true, "")
	// a dead (sooner) vs b suspect (later); x suspect (later) vs y dead (sooner).
	p.ipHealth["a"] = &healthRec{state: stateDead, nextRetest: 1005}
	p.ipHealth["b"] = &healthRec{state: stateSuspect, nextRetest: 1100}
	p.sniHealth["x"] = &healthRec{state: stateSuspect, nextRetest: 1050}
	p.sniHealth["y"] = &healthRec{state: stateDead, nextRetest: 1010}
	ip, sni, ok := p.current()
	if !ok {
		t.Fatal("fallback must still return a combo")
	}
	if ip != "b" || sni.host != "x" {
		t.Fatalf("least-bad should prefer suspect over dead: want b/x, got %s/%s", ip, sni.host)
	}
	// Within the same tier, the soonest nextRetest wins.
	p.ipHealth["a"] = &healthRec{state: stateSuspect, nextRetest: 1005}
	p.ipHealth["b"] = &healthRec{state: stateSuspect, nextRetest: 1100}
	if ip, _, _ := p.current(); ip != "a" {
		t.Fatalf("same-tier tiebreak should pick soonest retest a, got %s", ip)
	}
}

// The status snapshot carries the full per-entry FSM state, and keeps the legacy burned arrays
// populated with the suspect-or-dead keys.
func TestStatusSnapshotStates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "st.json")
	p, now := clockPool([]string{"a", "b"}, snis("x"), true, path)
	p.current() // sets active
	p.markSuspect("ip", "a", "test")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("status file not written: %v", err)
	}
	var st struct {
		Active     string   `json:"active"`
		BurnedIPs  []string `json:"burned_ips"`
		BurnedSNIs []string `json:"burned_snis"`
		Health     []struct {
			Key        string `json:"key"`
			Kind       string `json:"kind"`
			State      string `json:"state"`
			Fails      int    `json:"fails"`
			NextRetest int64  `json:"next_retest_unix"`
		} `json:"health"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("bad status json: %v", err)
	}
	got := map[string]string{} // key -> state
	var aNext int64
	for _, h := range st.Health {
		got[h.Kind+":"+h.Key] = h.State
		if h.Kind == "ip" && h.Key == "a" {
			aNext = h.NextRetest
		}
	}
	if got["ip:a"] != stateSuspect || got["ip:b"] != "healthy" || got["sni:x"] != "healthy" {
		t.Fatalf("health states wrong: %v", got)
	}
	if aNext != *now+30 {
		t.Fatalf("suspect a next_retest_unix=%d, want %d", aNext, *now+30)
	}
	if len(st.BurnedIPs) != 1 || st.BurnedIPs[0] != "a" {
		t.Fatalf("expected burned_ips=[a], got %v", st.BurnedIPs)
	}
	if len(st.BurnedSNIs) != 0 {
		t.Fatalf("expected no burned_snis, got %v", st.BurnedSNIs)
	}
}

// dueRetests reports only entries whose backoff has elapsed; probeNow pulls one forward so the
// scheduler picks it up on the next tick, paired with a healthy partner on the other axis.
func TestDueRetestsAndProbeNow(t *testing.T) {
	p, now := clockPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p.markSuspect("ip", "a", "test") // due at now+30
	if due := p.dueRetests(); len(due) != 0 {
		t.Fatalf("nothing should be due yet, got %v", due)
	}
	p.probeNow("ip", "a")
	due := p.dueRetests()
	if len(due) != 1 || due[0].kind != "ip" || due[0].key != "a" {
		t.Fatalf("probeNow should make a due, got %v", due)
	}
	if due[0].ip != "a" {
		t.Fatalf("retest spec should dial the entry itself, got %q", due[0].ip)
	}
	if p.sniHealth[due[0].sni.host] != nil {
		t.Fatalf("retest partner SNI must be healthy, got %q", due[0].sni.host)
	}
	// After the backoff elapses on the clock, it is due without probeNow too.
	p2, now2 := clockPool([]string{"a"}, snis("x"), true, "")
	p2.markSuspect("ip", "a", "test")
	*now2 = *now + 31
	if due := p2.dueRetests(); len(due) != 1 {
		t.Fatalf("entry should be due once its backoff elapses, got %v", due)
	}
}

// altHealthy* feed the differential probe: they return a healthy partner on the other axis,
// excluding the failed one, and report false when none exists.
func TestAltHealthyLookups(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	if s, ok := p.altHealthySNI("x"); !ok || s.host != "y" {
		t.Fatalf("altHealthySNI(x) = %q ok=%v, want y", s.host, ok)
	}
	if ip, ok := p.altHealthyIP("a"); !ok || ip != "b" {
		t.Fatalf("altHealthyIP(a) = %q ok=%v, want b", ip, ok)
	}
	p.markSuspect("sni", "y", "test") // now y is not healthy
	if _, ok := p.altHealthySNI("x"); ok {
		t.Fatal("no healthy SNI other than x should remain")
	}
}

// selectEntry pins a specific edge: it moves the index onto that entry and clears any
// suspect/dead mark so current() picks it, even if it was blocked a moment ago.
func TestSelectEntryPinsAndClears(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")
	p.markSuspect("ip", "b", "test") // b was blocked
	if !p.selectEntry("ip", "b") {
		t.Fatal("selectEntry should find b")
	}
	if p.ipHealth["b"] != nil {
		t.Fatal("selecting b must clear its suspect mark")
	}
	if ip, _, ok := p.current(); !ok || ip != "b" {
		t.Fatalf("current() should now return the selected b, got %q ok=%v", ip, ok)
	}
	if p.selectEntry("ip", "does-not-exist") {
		t.Fatal("selectEntry must return false for an unknown key")
	}
}

// TestPinOneShot locks down the fix: a pin is a ONE-SHOT exact jump. Within its short window it
// FORCES exactly the chosen edge (no drift onto a neighbour — the reported "pin #3 -> #2" bug —
// even across advance()/a suspect partner/a fresh burn); after the window it clears and normal
// rotation resumes (it does NOT lock forever).
func TestPinOneShot(t *testing.T) {
	p, now := clockPool([]string{"a", "b", "c"}, snis("x", "y"), true, "")
	p.markSuspect("sni", "x", "test") // messy partner axis
	p.markSuspect("ip", "a", "test")
	if !p.selectEntry("ip", "c") {
		t.Fatal("selectEntry should find c")
	}
	if !p.isPinned() {
		t.Fatal("pool should report pinned right after selectEntry")
	}
	// Within the window: current() forces c every time, across rotation attempts and a fresh burn.
	for i := 0; i < 6; i++ {
		if ip, _, ok := p.current(); !ok || ip != "c" {
			t.Fatalf("pin must force ip=c on dial %d, got %q ok=%v", i, ip, ok)
		}
		p.advance()
		p.advanceIP()
	}
	p.markSuspect("ip", "c", "test")
	if ip, _, _ := p.current(); ip != "c" {
		t.Fatalf("within the pin window a suspect mark must not override the pin, got %q", ip)
	}
	// After the window the pin expires and rotation resumes: c is suspect, so current() must move
	// off it to a healthy edge (proving it is no longer forced / not sticky-forever).
	*now += pinTTL + 1
	if p.isPinned() {
		t.Fatal("pin must expire after pinTTL")
	}
	if ip, _, _ := p.current(); ip == "c" {
		t.Fatalf("after the pin expires a suspect edge must not be forced; got %q", ip)
	}
}

func TestAutoBurnOffNoTracking(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), false, "") // manual-only
	p.markSuspect("ip", "a", "test")                         // must NOT track
	if p.ipHealth["a"] != nil {
		t.Fatalf("autoBurn=off must not sideline an entry, got %#v", p.ipHealth["a"])
	}
	got := map[string]bool{}
	for i := 0; i < 4; i++ {
		ip, _, ok := p.current()
		if !ok {
			t.Fatal("pool empty with autoBurn off")
		}
		got[ip] = true
		p.advance()
	}
	if !got["a"] || !got["b"] {
		t.Fatalf("autoBurn=off should keep all IPs; got %v", got)
	}
}

// TestAdvanceIPAndSNIIndependently checks the manual per-dimension "rotate now": advanceIP
// steps the IP while the SNI stays put, and advanceSNI does the reverse.
func TestAdvanceIPAndSNIIndependently(t *testing.T) {
	p := newWSPool([]string{"a", "b", "c"}, snis("x", "y"), true, "")
	ip0, sni0, _ := p.current()
	if ip0 != "a" || sni0.host != "x" {
		t.Fatalf("start = %s/%s, want a/x", ip0, sni0.host)
	}
	p.advanceIP()
	ip1, sni1, _ := p.current()
	if ip1 != "b" || sni1.host != "x" {
		t.Fatalf("after advanceIP = %s/%s, want b/x (SNI unchanged)", ip1, sni1.host)
	}
	p.advanceSNI()
	ip2, sni2, _ := p.current()
	if ip2 != "b" || sni2.host != "y" {
		t.Fatalf("after advanceSNI = %s/%s, want b/y (IP unchanged)", ip2, sni2.host)
	}
	p.advanceIP()
	p.advanceIP()
	ip3, _, _ := p.current()
	if ip3 != "a" {
		t.Fatalf("after wrap = %s, want a", ip3)
	}
}

// TestDataPlaneFaultBurn locks down C1: a carrier that connects then dies quickly (throttle /
// blackhole-after-handshake) is attributed to its IP after dataFailThreshold short deaths — but
// only with a recent good session (outage guard) and a healthy alternative (never strand the pool).
func TestDataPlaneFaultBurn(t *testing.T) {
	p, _ := clockPool([]string{"a", "b", "c"}, snis("x"), true, "")

	// Outage guard: with no recent good session, short deaths must NOT burn (server/local outage).
	p.dataFailure("a")
	p.dataFailure("a")
	if p.ipHealth["a"] != nil {
		t.Fatal("burned an IP with no recent good session (outage guard failed)")
	}

	// A good session elsewhere arms attribution; then it takes the threshold to burn.
	p.dataSuccess("b")
	p.dataFailure("a")
	if p.ipHealth["a"] != nil {
		t.Fatal("burned after a single data fault; want threshold")
	}
	p.dataFailure("a")
	if p.ipHealth["a"] == nil || p.ipHealth["a"].state != stateSuspect {
		t.Fatal("expected 'a' suspect after dataFailThreshold short deaths")
	}
	if p.ipHealth["a"].nextRetest != 1000+suspectBackoff[2] {
		t.Fatalf("data-plane suspect should use the longer backoff, got nextRetest=%d", p.ipHealth["a"].nextRetest)
	}

	// dataSuccess resets the per-IP counter.
	p.dataFailure("c")
	p.dataSuccess("c")
	p.dataFailure("c")
	if p.ipHealth["c"] != nil {
		t.Fatal("dataSuccess should have reset c's fault counter")
	}

	// No healthy alternative -> never strand the pool (don't burn the last usable IP).
	p2, _ := clockPool([]string{"d", "e"}, snis("x"), true, "")
	p2.dataSuccess("e")
	p2.ipHealth["e"] = &healthRec{state: stateDead, nextRetest: 1 << 40} // only 'd' remains usable
	p2.dataFailure("d")
	p2.dataFailure("d")
	if p2.ipHealth["d"] != nil {
		t.Fatal("burned the last healthy IP (no-alt guard failed)")
	}

	// autoBurn off -> data faults are ignored entirely.
	p3, _ := clockPool([]string{"a", "b"}, snis("x"), false, "")
	p3.dataSuccess("b")
	p3.dataFailure("a")
	p3.dataFailure("a")
	if p3.ipHealth["a"] != nil {
		t.Fatal("data fault burned an edge with autoBurn off")
	}
}

// TestDifferentialProbeVerdicts locks down the REPRODUCE-FIRST prober: a working combo is a
// transient blip (blame nothing), and a confirmed-down combo is attributed to the axis that
// still works in isolation — deterministically, with no dependence on goroutine scheduling
// (the old racing version could blame a random axis when every edge was reachable).
func TestDifferentialProbeVerdicts(t *testing.T) {
	// reach is the set of "ip|sni" combos the fake oracle reports as reachable.
	mk := func(ips []string, hosts []string, reach map[string]bool) *TCP {
		p := newWSPool(ips, snis(hosts...), true, "")
		b := &TCP{pool: p}
		b.probeFn = func(ip string, sni wsSNIEntry) bool { return reach[ip+"|"+sni.host] }
		return b
	}
	all := func(ips, hosts []string, except ...string) map[string]bool {
		skip := map[string]bool{}
		for _, s := range except {
			skip[s] = true
		}
		m := map[string]bool{}
		for _, ip := range ips {
			for _, h := range hosts {
				k := ip + "|" + h
				m[k] = !skip[k] && !skip[ip] && !skip[h]
			}
		}
		return m
	}
	ips := []string{"ip1", "ip2"}
	hosts := []string{"s1", "s2"}
	fail := wsSNIEntry{host: "s1", path: "/"}

	// transient: the failing combo works on re-probe -> blame nothing.
	if v := mk(ips, hosts, all(ips, hosts)).differentialProbe("ip1", fail); v != verdictTransient {
		t.Fatalf("reachable combo: got %v, want transient", v)
	}
	// IP guilty: ip1 is dead everywhere; s1 works on ip2.
	if v := mk(ips, hosts, all(ips, hosts, "ip1")).differentialProbe("ip1", fail); v != verdictIPGuilty {
		t.Fatalf("dead ip: got %v, want IP-guilty", v)
	}
	// SNI guilty: s1 is dead everywhere; ip1 works with s2.
	if v := mk(ips, hosts, all(ips, hosts, "s1")).differentialProbe("ip1", fail); v != verdictSNIGuilty {
		t.Fatalf("dead sni: got %v, want SNI-guilty", v)
	}
	// both dead but the client uplink is fine (altIP+altSNI works): pin the IP (SNI heals on retest).
	if v := mk(ips, hosts, all(ips, hosts, "ip1", "s1")).differentialProbe("ip1", fail); v != verdictIPGuilty {
		t.Fatalf("both dead: got %v, want IP-guilty", v)
	}
	// local/broad outage: NOTHING is reachable (client uplink down) -> blame nothing, never burn a clean edge.
	if v := mk(ips, hosts, map[string]bool{}).differentialProbe("ip1", fail); v != verdictUnknown {
		t.Fatalf("local outage: got %v, want unknown (no false burn)", v)
	}
	// single SNI, dead IP (the screenshot case: 2 IPs, 1 SNI) -> IP guilty, never blames the lone SNI.
	if v := mk(ips, []string{"s1"}, all(ips, []string{"s1"}, "ip1")).differentialProbe("ip1", fail); v != verdictIPGuilty {
		t.Fatalf("single-sni dead ip: got %v, want IP-guilty", v)
	}
	// single edge (1 IP, 1 SNI) down -> nothing to compare -> unknown.
	if v := mk([]string{"ip1"}, []string{"s1"}, map[string]bool{}).differentialProbe("ip1", fail); v != verdictUnknown {
		t.Fatalf("single edge down: got %v, want unknown", v)
	}
}
