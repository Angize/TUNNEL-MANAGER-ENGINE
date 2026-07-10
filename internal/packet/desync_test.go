//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestNewDesyncCfgDefaults locks in the defaulting (mirrors the node/panel defaults).
func TestNewDesyncCfgDefaults(t *testing.T) {
	if d := newDesyncCfg(false, 9, 9, "both"); d.on {
		t.Fatal("off flag must yield the zero (off) config regardless of other args")
	}
	d := newDesyncCfg(true, 0, 0, "")
	if !d.on || d.ttl != 4 || d.count != 2 || d.mode != "ttl" {
		t.Fatalf("defaults wrong: %+v (want on ttl=4 count=2 mode=ttl)", d)
	}
	if got := newDesyncCfg(true, 7, 5, "garbage"); got.mode != "ttl" {
		t.Fatalf("unknown mode must fall back to ttl, got %q", got.mode)
	}
	if got := newDesyncCfg(true, 7, 5, "badsum"); got.ttl != 7 || got.count != 5 || got.mode != "badsum" {
		t.Fatalf("explicit values not preserved: %+v", got)
	}
}

// TestDesyncSpecs checks the per-decoy header knobs for each mode: a ttl decoy keeps a live
// checksum + the low TTL; a badsum decoy keeps a normal TTL; "both" alternates.
func TestDesyncSpecs(t *testing.T) {
	if s := (desyncCfg{}).specs(); s != nil {
		t.Fatal("off config must produce no specs")
	}
	ttlS := newDesyncCfg(true, 3, 3, "ttl").specs()
	if len(ttlS) != 3 {
		t.Fatalf("ttl mode: want 3 specs, got %d", len(ttlS))
	}
	for i, s := range ttlS {
		if s.badSum || s.ttl != 3 {
			t.Fatalf("ttl spec %d wrong: %+v", i, s)
		}
	}
	badS := newDesyncCfg(true, 3, 2, "badsum").specs()
	for i, s := range badS {
		if !s.badSum || s.ttl != 64 {
			t.Fatalf("badsum spec %d wrong: %+v (want badSum + ttl 64)", i, s)
		}
	}
	bothS := newDesyncCfg(true, 5, 4, "both").specs()
	if len(bothS) != 4 {
		t.Fatalf("both mode: want 4 specs, got %d", len(bothS))
	}
	// even index -> ttl decoy (low ttl, good sum); odd -> badsum decoy (ttl 64, bad sum)
	for i, s := range bothS {
		if i%2 == 0 && (s.badSum || s.ttl != 5) {
			t.Fatalf("both spec %d (even) should be a ttl decoy: %+v", i, s)
		}
		if i%2 == 1 && (!s.badSum || s.ttl != 64) {
			t.Fatalf("both spec %d (odd) should be a badsum decoy: %+v", i, s)
		}
	}
}

// TestBuildIP4Ext verifies the header fields, that buildIP4 is byte-identical to the
// explicit (ttl 64, good checksum) form, that a good checksum verifies to zero, and that
// badSum deliberately breaks it.
func TestBuildIP4Ext(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	payload := []byte("hello desync")

	base := buildIP4(src, dst, protoBIP, payload)
	ext := buildIP4Ext(src, dst, protoBIP, 64, false, payload)
	if string(base) != string(ext) {
		t.Fatal("buildIP4 must equal buildIP4Ext(...,64,false,...) byte-for-byte")
	}
	if base[8] != 64 {
		t.Fatalf("default TTL byte = %d, want 64", base[8])
	}
	if base[9] != byte(protoBIP) {
		t.Fatalf("proto byte = %d, want %d", base[9], protoBIP)
	}
	// A valid IPv4 header sums (one's complement, including the stored checksum) to zero.
	if s := onesComplementSum(base[:20]); s != 0 {
		t.Fatalf("valid header checksum should verify to 0, got %#04x", s)
	}

	low := buildIP4Ext(src, dst, protoBIP, 3, false, payload)
	if low[8] != 3 {
		t.Fatalf("low-TTL header TTL = %d, want 3", low[8])
	}
	if s := onesComplementSum(low[:20]); s != 0 {
		t.Fatalf("low-TTL header must still have a VALID checksum, got %#04x", s)
	}

	bad := buildIP4Ext(src, dst, protoBIP, 64, true, payload)
	if s := onesComplementSum(bad[:20]); s == 0 {
		t.Fatal("badSum header must NOT verify (checksum should be corrupted)")
	}
	// The only difference from a good header is the checksum field — everything else identical.
	good := buildIP4Ext(src, dst, protoBIP, 64, false, payload)
	if binary.BigEndian.Uint16(bad[10:12]) == binary.BigEndian.Uint16(good[10:12]) {
		t.Fatal("badSum checksum must differ from the correct one")
	}
	bad[10], bad[11] = good[10], good[11]
	if string(bad) != string(good) {
		t.Fatal("badSum must corrupt ONLY the checksum field, nothing else")
	}
}

// TestBuildIP4ExtBadSumZeroTwin locks in the one's-complement zero-twin fix: when the correct
// header checksum is 0x0000, its bitwise complement 0xffff ALSO verifies (both are valid
// representations of zero), so a naive ^sum would leave a VALID checksum. buildIP4Ext must
// still produce an invalid one. src=10.0.0.0 dst=192.168.1.0 proto=253 ttl=238 len(payload)=69
// is a header whose correct checksum is exactly 0x0000.
func TestBuildIP4ExtBadSumZeroTwin(t *testing.T) {
	src := net.IPv4(10, 0, 0, 0)
	dst := net.IPv4(192, 168, 1, 0)
	payload := make([]byte, 69)

	good := buildIP4Ext(src, dst, protoBIP, 238, false, payload)
	if binary.BigEndian.Uint16(good[10:12]) != 0x0000 {
		t.Fatalf("test premise broken: correct checksum should be 0x0000, got %#04x", binary.BigEndian.Uint16(good[10:12]))
	}
	if onesComplementSum(good[:20]) != 0 {
		t.Fatal("the 0x0000-checksum header must itself verify")
	}
	bad := buildIP4Ext(src, dst, protoBIP, 238, true, payload)
	if onesComplementSum(bad[:20]) == 0 {
		t.Fatalf("badSum header STILL verifies (zero-twin not handled): checksum=%#04x", binary.BigEndian.Uint16(bad[10:12]))
	}
}

// TestBuildIP4ExtTTLClamp checks the TTL is clamped into 1..255 (a 0 or negative TTL would
// be an instantly-dead packet or a malformed byte).
func TestBuildIP4ExtTTLClamp(t *testing.T) {
	src, dst := net.IPv4(1, 1, 1, 1), net.IPv4(2, 2, 2, 2)
	if p := buildIP4Ext(src, dst, protoUDP, 0, false, nil); p[8] != 1 {
		t.Fatalf("ttl 0 should clamp to 1, got %d", p[8])
	}
	if p := buildIP4Ext(src, dst, protoUDP, 999, false, nil); p[8] != 255 {
		t.Fatalf("ttl 999 should clamp to 255, got %d", p[8])
	}
}

// TestSpecsTCP checks the kernel-TCP inject path keeps EVERY decoy at the low TTL (never the
// 64 that specs() promotes badsum to), because a well-formed segment on a real 4-tuple must not
// reach the server. badSum still varies per mode.
func TestSpecsTCP(t *testing.T) {
	both := newDesyncCfg(true, 3, 4, "both").specsTCP()
	if len(both) != 4 {
		t.Fatalf("want 4 specs, got %d", len(both))
	}
	for i, s := range both {
		if s.ttl != 3 {
			t.Fatalf("specsTCP decoy %d has ttl %d, want the low 3 (never promoted to 64)", i, s.ttl)
		}
		wantBad := i%2 == 1
		if s.badSum != wantBad {
			t.Fatalf("specsTCP decoy %d badSum=%v, want %v", i, s.badSum, wantBad)
		}
	}
	for _, s := range newDesyncCfg(true, 5, 2, "badsum").specsTCP() {
		if s.ttl != 5 || !s.badSum {
			t.Fatalf("badsum-mode TCP spec should be low-ttl + badSum, got %+v", s)
		}
	}
	// A high fake_ttl must be clamped on the inject path so a well-formed decoy can't reach the
	// server (it would draw an RST / challenge-ACK on the real 4-tuple).
	for i, s := range newDesyncCfg(true, 64, 3, "both").specsTCP() {
		if s.ttl != injectMaxTTL {
			t.Fatalf("specsTCP decoy %d: ttl 64 should clamp to %d, got %d", i, injectMaxTTL, s.ttl)
		}
	}
}

// TestBuildTCPSeg checks the crafted segment has the right ports/flags and a VALID TCP checksum
// (recomputing over the segment with the stored checksum in place sums to zero).
func TestBuildTCPSeg(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 1, 2)
	seg := buildTCPSeg(src, dst, 40000, 443, 0x11223344, 0x55667788, tcpPshAck, 0xffff, []byte("decoy-body"))
	if binary.BigEndian.Uint16(seg[0:2]) != 40000 || binary.BigEndian.Uint16(seg[2:4]) != 443 {
		t.Fatal("ports not stamped correctly")
	}
	if seg[13] != tcpPshAck {
		t.Fatalf("flags = %#x, want PSH|ACK %#x", seg[13], tcpPshAck)
	}
	if binary.BigEndian.Uint32(seg[4:8]) != 0x11223344 || binary.BigEndian.Uint32(seg[8:12]) != 0x55667788 {
		t.Fatal("seq/ack not stamped")
	}
	// A valid TCP checksum: the pseudo-header + segment (checksum in place) one's-complement to 0.
	if s := l4Checksum(src, dst, protoTCP, seg); s != 0 {
		t.Fatalf("TCP checksum should verify to 0, got %#04x", s)
	}
}

// TestFakePayload checks the decoy payload stays in the intended plausible-frame size band.
func TestFakePayload(t *testing.T) {
	for i := 0; i < 200; i++ {
		n := len(fakePayload())
		if n < 48 || n > 111 {
			t.Fatalf("fakePayload len %d out of the 48..111 band", n)
		}
	}
}
