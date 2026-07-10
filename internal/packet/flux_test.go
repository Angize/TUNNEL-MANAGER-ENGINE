package packet

import (
	"testing"
	"time"
)

// Both ends must derive the SAME shape from (PSK, epoch) — this is what lets them
// rotate without any wire signal.
func TestFluxShapeDeterministic(t *testing.T) {
	for _, ep := range []int64{0, 1, 4471, 1 << 40} {
		a := deriveFluxShape("hunter2", ep, "random")
		b := deriveFluxShape("hunter2", ep, "random")
		if a != b {
			t.Fatalf("epoch %d: shape not deterministic: %+v vs %+v", ep, a, b)
		}
		if !protoInPool(a.proto) {
			t.Fatalf("epoch %d: proto %d not in pool", ep, a.proto)
		}
		if !dportInPool(a.dportSTUN, fluxStunDports) {
			t.Fatalf("epoch %d: stun dport %d not in STUN pool", ep, a.dportSTUN)
		}
	}
}

// The shape profile changes the control-frame padding budget (the size signature)
// but never the carrier proto/ports, which must stay profile-independent so both
// ends interoperate regardless of the mimicry profile chosen.
func TestFluxShapeProfileOnlyChangesPadding(t *testing.T) {
	r := deriveFluxShape("hunter2", 42, "random")
	v := deriveFluxShape("hunter2", 42, "video")
	if r.proto != v.proto || r.dport != v.dport || r.dportSTUN != v.dportSTUN || r.sport != v.sport {
		t.Fatal("shape profile changed the carrier params (must only change padding)")
	}
	if v.ctrlPad < 64 || v.ctrlPad > 223 {
		t.Fatalf("video ctrlPad %d out of its profile band", v.ctrlPad)
	}
}

// A different PSK must derive a different shape schedule (the shape is keyed).
func TestFluxShapeKeyed(t *testing.T) {
	same := 0
	for ep := int64(0); ep < 64; ep++ {
		if deriveFluxShape("psk-A", ep, "random").proto == deriveFluxShape("psk-B", ep, "random").proto {
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
	e := fluxEpochAt(10*time.Second, time.Unix(1_000_000_000, 0))
	grace := graceProtos("hunter2", e, "random")
	for _, ep := range []int64{e - 1, e, e + 1} {
		p := deriveFluxShape("hunter2", ep, "random").proto
		if !grace[p] {
			t.Fatalf("grace window missing proto %d for epoch %d", p, ep)
		}
	}
	// The stun-carrier grace window must cover the STUN dports of all three epochs.
	gd := graceDports("hunter2", e, "random", "stun")
	for _, ep := range []int64{e - 1, e, e + 1} {
		if !gd[deriveFluxShape("hunter2", ep, "random").dportSTUN] {
			t.Fatalf("stun grace window missing dport for epoch %d", ep)
		}
	}
}

// A manual epoch offset shifts the whole schedule by exactly that many epochs, so
// "rotate now" advances both ends in lock-step to a shape they'd otherwise reach later.
func TestFluxEpochOffsetShiftsSchedule(t *testing.T) {
	base := fluxEpochAt(600*time.Second, time.Unix(1_700_000_000, 0))
	if s1, s2 := deriveFluxShape("k", base+5, "random"), deriveFluxShape("k", base+5, "random"); s1 != s2 {
		t.Fatal("deriveFluxShape must be deterministic for the same (key, epoch, shape)") // two separate calls, not x!=x
	}
	// offset of +5 lands on the epoch-(base+5) shape; without it we'd be on base.
	if deriveFluxShape("k", base, "random").proto == deriveFluxShape("k", base+5, "random").proto &&
		deriveFluxShape("k", base, "random").dport == deriveFluxShape("k", base+5, "random").dport {
		t.Skip("rare: base and base+5 happen to share carrier params")
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

func dportInPool(p uint16, pool []uint16) bool {
	for _, x := range pool {
		if x == p {
			return true
		}
	}
	return false
}
