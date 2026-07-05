package packet

import "testing"

func TestReplayGuardBasics(t *testing.T) {
	var g replayGuard
	if !g.ok(1, 1) {
		t.Fatal("first frame must be accepted")
	}
	if g.ok(1, 1) {
		t.Fatal("exact duplicate must be rejected")
	}
	if !g.ok(1, 2) {
		t.Fatal("next in-order frame must be accepted")
	}
	if !g.ok(1, 5) {
		t.Fatal("forward jump must be accepted")
	}
	if !g.ok(1, 3) {
		t.Fatal("in-window out-of-order frame must be accepted once")
	}
	if g.ok(1, 3) {
		t.Fatal("replay of an in-window frame must be rejected")
	}
	if g.ok(1, 5) {
		t.Fatal("replay of the current top must be rejected")
	}
}

func TestReplayGuardTooOld(t *testing.T) {
	var g replayGuard
	g.ok(1, 100)
	if g.ok(1, 100-replayWindow) {
		t.Fatal("a frame older than the window must be rejected")
	}
	if !g.ok(1, 99) {
		t.Fatal("a frame just inside the window must be accepted")
	}
}

func TestReplayGuardSessionReset(t *testing.T) {
	var g replayGuard
	g.ok(7, 500)
	// A new session id (peer restarted: fresh prefix, counter back to 1) resets
	// the window so the reconnect is accepted even though seq went backwards.
	if !g.ok(8, 1) {
		t.Fatal("a new session must adopt and accept, enabling reconnect")
	}
	if g.ok(8, 1) {
		t.Fatal("duplicate under the new session must still be rejected")
	}
}

func TestReplayGuardFarForwardShift(t *testing.T) {
	var g replayGuard
	g.ok(1, 1)
	if !g.ok(1, 1_000_000) {
		t.Fatal("a large forward jump must be accepted")
	}
	if g.ok(1, 1) {
		t.Fatal("an ancient frame after a big jump must be rejected")
	}
}
