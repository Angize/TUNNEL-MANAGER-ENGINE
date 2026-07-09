package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCoreStatusEventPairing verifies the datagram self-heal event contract: the initial connect is
// silent (no spurious "reconnect"), a stale-detect emits one "down", and only then does a connect
// emit a "reconnect" — and the status file is written with a monotonic seq the panel consumes once.
func TestCoreStatusEventPairing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-x.status")
	s := newCoreStatus(path, "udp · 1.2.3.4:443")

	// First connect at startup must NOT be logged as a self-heal.
	s.reconnected("udp")
	if got := readEvents(t, path); len(got) != 0 {
		t.Fatalf("initial connect should be silent; got %d events: %+v", len(got), got)
	}

	// A stale-detect emits exactly one down.
	s.down("stale", "udp")
	evs := readEvents(t, path)
	if len(evs) != 1 || evs[0].Kind != "down" || evs[0].Code != "stale" {
		t.Fatalf("after down: want 1 down/stale, got %+v", evs)
	}

	// The recovery that follows emits one up/reconnect.
	s.reconnected("udp")
	evs = readEvents(t, path)
	if len(evs) != 2 || evs[1].Kind != "up" || evs[1].Code != "reconnect" {
		t.Fatalf("after recovery: want down then up/reconnect, got %+v", evs)
	}
	if evs[0].Seq >= evs[1].Seq {
		t.Fatalf("seq must be monotonic: %d then %d", evs[0].Seq, evs[1].Seq)
	}

	// A second recovery with no intervening down must be silent (no dangling pair).
	s.reconnected("udp")
	if evs = readEvents(t, path); len(evs) != 2 {
		t.Fatalf("recovery without a pending down must be silent; got %d events", len(evs))
	}

	// A nil writer (server side / status off) is a safe no-op.
	var off *coreStatus
	off.down("stale", "udp")
	off.reconnected("udp")
	off.event("down", "stale", "udp")
}

func readEvents(t *testing.T, path string) []coreEvent {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var st struct {
		Events []coreEvent `json:"events"`
	}
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	return st.Events
}
