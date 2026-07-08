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
