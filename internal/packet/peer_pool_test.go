package packet

import "testing"

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

func TestPeerPoolRevivesWhenAllBurned(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.fail() // burn a -> advance to b
	// burning the last live endpoint must revive all AND still move (never dead-end, never re-stick)
	a, moved := p.fail() // burn b -> revive all, advance off b back to a
	// after revival nothing is burned; both are candidates again
	p.mu.Lock()
	nb := len(p.burned)
	p.mu.Unlock()
	if nb != 0 {
		t.Fatalf("all-burned should revive to 0 burned, got %d", nb)
	}
	if !moved || a != "a" {
		t.Fatalf("after all-burned revive: got %q moved=%v, want a true (advance off the failed endpoint)", a, moved)
	}
}

func TestPeerPoolAutoBurnOffJustRotates(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, false, 0, "") // auto-burn OFF
	p.fail()
	p.mu.Lock()
	nb := len(p.burned)
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
	p.succeeded()
	p.mu.Lock()
	burnedA := p.burned["a"]
	p.mu.Unlock()
	if burnedA {
		t.Fatal("succeeded() must clear the active endpoint's burn")
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
