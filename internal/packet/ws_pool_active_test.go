package packet

import "testing"

// TestActiveEdgeNotCorruptedByStandbyDial locks in the warm-standby bug fix: the status file's
// "active edge" must reflect the carrier ACTUALLY carrying data, never the edge a background
// standby dial happened to pick. current() picks an edge but must NOT publish it; only setActive
// (real active / promotion) does. Before the fix, current() set p.active, so building a standby
// clobbered the live active and the panel's auto-switch log went wrong / silent.
func TestActiveEdgeNotCorruptedByStandbyDial(t *testing.T) {
	snis := []wsSNIEntry{{host: "a.example"}, {host: "b.example"}}
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis, true, "")

	// current() picks an edge but must leave the published active empty.
	ip0, sni0, ok := p.current()
	if !ok {
		t.Fatal("current: pool empty")
	}
	if p.active != "" {
		t.Fatalf("current() must not publish the active edge; got %q", p.active)
	}

	// The client establishes the ACTIVE carrier on that edge and publishes it.
	activeCombo := activeLabel(ip0, sni0.host)
	p.setActive(activeCombo)
	if p.active != activeCombo {
		t.Fatalf("setActive: active = %q, want %q", p.active, activeCombo)
	}

	// A background warm-standby dial calls current() again (advancing to a different edge). This
	// MUST NOT change the live active edge.
	p.advance()
	ipS, sniS, _ := p.current()
	standbyCombo := activeLabel(ipS, sniS.host)
	if standbyCombo == activeCombo {
		t.Fatal("test setup: standby landed on the same edge as active")
	}
	if p.active != activeCombo {
		t.Fatalf("standby dial corrupted the active edge: active = %q, want %q", p.active, activeCombo)
	}

	// On promotion, the standby becomes the live active and IS published.
	p.setActive(standbyCombo)
	if p.active != standbyCombo {
		t.Fatalf("promote: active = %q, want %q", p.active, standbyCombo)
	}
}
