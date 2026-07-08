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

func TestBurnIPExcludesIt(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), true, "")
	p.burnIP("a") // a is dead; only b remains
	for i := 0; i < 5; i++ {
		ip, _, ok := p.current()
		if !ok || ip != "b" {
			t.Fatalf("expected only b after burning a, got ip=%q ok=%v", ip, ok)
		}
		p.advance()
	}
}

func TestBurnSNIExcludesIt(t *testing.T) {
	p := newWSPool([]string{"a"}, snis("x", "y"), true, "")
	p.burnSNI("x")
	for i := 0; i < 4; i++ {
		_, sni, ok := p.current()
		if !ok || sni.host != "y" {
			t.Fatalf("expected only y after burning x, got %q ok=%v", sni.host, ok)
		}
		p.advance()
	}
}

// A single ambiguous (TLS/WS) failure attributes to nothing — we can't yet tell whether
// the IP or the SNI is at fault, so neither is burned.
func TestHandshakeFailSingleBurnsNothing(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p.handshakeFailed("a", "x")
	if p.burnedIP["a"] || p.burnedSNI["x"] {
		t.Fatalf("a single ambiguous failure must burn nothing; burnedIP=%v burnedSNI=%v", p.burnedIP, p.burnedSNI)
	}
}

// A dead edge IP (TCP connects, then resets TLS) fails across several SNIs → the IP is
// burned and the healthy SNIs it dragged down are NOT. This is the reported bug.
func TestHandshakeFailBurnsIPNotHealthySNI(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p.handshakeFailed("a", "x")
	p.handshakeFailed("a", "y") // a has now failed 2 distinct SNIs → a is the culprit
	if !p.burnedIP["a"] {
		t.Fatal("IP a should burn after failing across 2 distinct SNIs")
	}
	if p.burnedSNI["x"] || p.burnedSNI["y"] {
		t.Fatalf("healthy SNIs must survive a bad IP; burnedSNI=%v", p.burnedSNI)
	}
}

// A genuinely blocked domain fails across several IPs → the SNI is burned, the IPs are not.
func TestHandshakeFailBurnsSNINotHealthyIP(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p.handshakeFailed("a", "x")
	p.handshakeFailed("b", "x") // x has now failed on 2 distinct IPs → x is the culprit
	if !p.burnedSNI["x"] {
		t.Fatal("SNI x should burn after failing across 2 distinct IPs")
	}
	if p.burnedIP["a"] || p.burnedIP["b"] {
		t.Fatalf("healthy IPs must survive a bad SNI; burnedIP=%v", p.burnedIP)
	}
}

// Two dead IPs sharing the same healthy SNI must not add up to burn that SNI: once an IP
// is burned its blame votes are dropped, so they can't push a good domain over the line.
func TestBurnedIPVotesDoNotBurnSharedSNI(t *testing.T) {
	p := newWSPool([]string{"a", "b", "c"}, snis("x", "y"), true, "")
	p.handshakeFailed("a", "x")
	p.handshakeFailed("a", "y") // a burned; its votes against x,y are dropped
	p.handshakeFailed("b", "x") // only b's vote against x remains
	if p.burnedSNI["x"] {
		t.Fatal("x wrongly burned: a burned IP's vote must not count against the SNI")
	}
	p.handshakeFailed("b", "y") // b burned
	if !p.burnedIP["a"] || !p.burnedIP["b"] {
		t.Fatal("both dead IPs should be burned")
	}
	if p.burnedSNI["x"] || p.burnedSNI["y"] {
		t.Fatalf("healthy SNIs survive two dead IPs; burnedSNI=%v", p.burnedSNI)
	}
}

// A success clears the accumulated blame, so an earlier transient failure never adds up.
func TestSuccessClearsBlame(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x", "y"), true, "")
	p.handshakeFailed("a", "x") // transient blip on (a,x)
	p.succeeded("a", "x")       // (a,x) later works
	p.handshakeFailed("a", "y") // fresh, unrelated failure
	if p.burnedIP["a"] {
		t.Fatal("a must not burn: the earlier (a,x) failure was cleared by its success")
	}
}

func TestExhaustionThenReset(t *testing.T) {
	p := newWSPool([]string{"a"}, snis("x"), true, "")
	p.burnIP("a")
	if _, _, ok := p.current(); ok {
		t.Fatal("expected exhausted pool")
	}
	p.resetBurns()
	if _, _, ok := p.current(); !ok {
		t.Fatal("expected pool usable after reset")
	}
}

func TestAutoBurnOffDoesNotPersist(t *testing.T) {
	p := newWSPool([]string{"a", "b"}, snis("x"), false, "") // manual-only
	p.burnIP("a")                                            // should NOT persist the burn, only step
	// both a and b must still be reachable across a full cycle
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

func TestStatusFileWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "st.json")
	p := newWSPool([]string{"a", "b"}, snis("x"), true, path)
	p.current() // sets active
	p.burnIP("a")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("status file not written: %v", err)
	}
	var st struct {
		Active     string   `json:"active"`
		BurnedIPs  []string `json:"burned_ips"`
		BurnedSNIs []string `json:"burned_snis"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("bad status json: %v", err)
	}
	if len(st.BurnedIPs) != 1 || st.BurnedIPs[0] != "a" {
		t.Fatalf("expected burned_ips=[a], got %v", st.BurnedIPs)
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
	// IP wraps a,b,c -> back to a after three advances.
	p.advanceIP()
	p.advanceIP()
	ip3, _, _ := p.current()
	if ip3 != "a" {
		t.Fatalf("after wrap = %s, want a", ip3)
	}
}
