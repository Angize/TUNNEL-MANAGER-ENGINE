package packet

import "testing"

// TestReassessRotationEvents checks the one-shot pool degraded/restored events: when a 2-IP pool loses
// an edge (only one healthy left) it emits exactly one "pool/degraded", does not repeat it, and emits
// exactly one "pool/restored" when the edge recovers — so the operator can see WHY the rotation log
// went quiet and when it resumed.
func TestReassessRotationEvents(t *testing.T) {
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, []wsSNIEntry{{host: "a.com"}}, true /*autoBurn*/, "" /*no status file*/)

	count := func(code string) int {
		p.mu.Lock()
		defer p.mu.Unlock()
		n := 0
		for _, e := range p.events {
			if e.Kind == "pool" && e.Code == code {
				n++
			}
		}
		return n
	}

	// Burn one of the two IPs -> only one healthy edge -> rotation paused.
	p.markSuspect("ip", "1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded events = %d, want 1", got)
	}
	if !p.rotDegraded {
		t.Fatal("rotDegraded should be set after losing an edge")
	}

	// A repeat burn of the SAME ip must not emit another degraded event (already degraded).
	p.markSuspect("ip", "1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded must not repeat, got %d", got)
	}

	// Recover the burned ip -> two healthy edges again -> rotation resumes.
	p.retestResult("ip", "1.1.1.1", true)
	if got := count("restored"); got != 1 {
		t.Fatalf("restored events = %d, want 1", got)
	}
	if p.rotDegraded {
		t.Fatal("rotDegraded should be cleared after recovery")
	}

	// A single-IP pool never rotated, so it must never emit these events.
	p1 := newWSPool([]string{"9.9.9.9"}, []wsSNIEntry{{host: "a.com"}}, true, "")
	p1.markSuspect("ip", "9.9.9.9", "test")
	p1.mu.Lock()
	for _, e := range p1.events {
		if e.Kind == "pool" {
			p1.mu.Unlock()
			t.Fatalf("single-ip pool emitted a pool event: %s", e.Code)
		}
	}
	p1.mu.Unlock()
}
