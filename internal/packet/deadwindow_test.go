package packet

import (
	"testing"
	"time"
)

// TestDeadWindow verifies the per-tunnel self-heal deadline resolution: 0 keeps the default, a set
// value overrides it, and the >=2×keepalive clamp protects a healthy pinging link from mis-reaping.
func TestDeadWindow(t *testing.T) {
	ka := 15 * time.Second
	def := 60 * time.Second
	cases := []struct {
		name     string
		deadSecs int
		want     time.Duration
	}{
		{"unset keeps default", 0, 60 * time.Second},
		{"negative keeps default", -5, 60 * time.Second},
		{"honored above clamp", 45, 45 * time.Second},
		{"honored at clamp", 30, 30 * time.Second},
		{"below clamp raised to 2xka", 10, 30 * time.Second}, // 10s < 2×15s → 30s
		{"just below clamp raised", 20, 30 * time.Second},
		{"max honored", 300, 300 * time.Second},
	}
	for _, c := range cases {
		if got := deadWindow(ka, c.deadSecs, def); got != c.want {
			t.Errorf("%s: deadWindow(%v, %d, %v) = %v, want %v", c.name, ka, c.deadSecs, def, got, c.want)
		}
	}
}

// TestTCPSetDeadAfter proves the per-tunnel override tightens the TCP-family read deadline (b.idle)
// below the default 60s floor, and is a no-op when unset.
func TestTCPSetDeadAfter(t *testing.T) {
	mk := func() *TCP { return &TCP{keepalive: 15 * time.Second, idle: idleFor(15 * time.Second)} }
	if b := mk(); b.idle != 60*time.Second {
		t.Fatalf("default idle = %v, want 60s", b.idle)
	}
	b := mk()
	b.SetDeadAfter(40)
	if b.idle != 40*time.Second {
		t.Errorf("after SetDeadAfter(40): idle = %v, want 40s", b.idle)
	}
	b2 := mk()
	b2.SetDeadAfter(0) // no-op
	if b2.idle != 60*time.Second {
		t.Errorf("SetDeadAfter(0) changed idle to %v, want unchanged 60s", b2.idle)
	}
	b3 := mk()
	b3.SetDeadAfter(10) // below 2×keepalive → clamped to 30s
	if b3.idle != 30*time.Second {
		t.Errorf("SetDeadAfter(10) with ka=15: idle = %v, want clamped 30s", b3.idle)
	}
}
