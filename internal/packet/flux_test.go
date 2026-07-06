package packet

import (
	"testing"
	"time"
)

// Both ends must derive the SAME shape from (PSK, epoch) — this is what lets them
// rotate without any wire signal.
func TestFluxShapeDeterministic(t *testing.T) {
	for _, ep := range []int64{0, 1, 4471, 1 << 40} {
		a := deriveFluxShape("hunter2", ep)
		b := deriveFluxShape("hunter2", ep)
		if a != b {
			t.Fatalf("epoch %d: shape not deterministic: %+v vs %+v", ep, a, b)
		}
		if !protoInPool(a.proto) {
			t.Fatalf("epoch %d: proto %d not in pool", ep, a.proto)
		}
		if a.padMax < 16 || a.padMax > 95 {
			t.Fatalf("epoch %d: padMax %d out of range", ep, a.padMax)
		}
	}
}

// A different PSK must derive a different shape schedule (the shape is keyed).
func TestFluxShapeKeyed(t *testing.T) {
	same := 0
	for ep := int64(0); ep < 64; ep++ {
		if deriveFluxShape("psk-A", ep).proto == deriveFluxShape("psk-B", ep).proto {
			same++
		}
	}
	// With 8 protocols, ~1/8 collisions are expected by chance; all-64 identical
	// would mean the PSK is not mixed in.
	if same == 64 {
		t.Fatal("two PSKs derived the identical protocol schedule — PSK not keyed into the shape")
	}
}

// The epoch index advances by exactly one per rotation period and is stable within it.
func TestFluxEpochBoundary(t *testing.T) {
	rotate := 10 * time.Second
	base := time.Unix(1_000_000_000, 0) // arbitrary fixed instant
	e0 := fluxEpochAt(rotate, base)
	if got := fluxEpochAt(rotate, base.Add(9*time.Second)); got != e0 {
		t.Fatalf("epoch changed within the period: %d != %d", got, e0)
	}
	if got := fluxEpochAt(rotate, base.Add(10*time.Second)); got != e0+1 {
		t.Fatalf("epoch did not advance at the boundary: %d != %d", got, e0+1)
	}
}

// The grace window must contain the current epoch's protocol plus its neighbours,
// so a frame sent just before a rotation still passes the receiver's filter.
func TestFluxGraceWindow(t *testing.T) {
	rotate := 10 * time.Second
	now := time.Unix(1_000_000_000, 0)
	grace := graceProtos("hunter2", rotate, now)
	e := fluxEpochAt(rotate, now)
	for _, ep := range []int64{e - 1, e, e + 1} {
		p := deriveFluxShape("hunter2", ep).proto
		if !grace[p] {
			t.Fatalf("grace window missing proto %d for epoch %d", p, ep)
		}
	}
}

func protoInPool(p int) bool {
	for _, x := range fluxProtoPool {
		if x == p {
			return true
		}
	}
	return false
}
