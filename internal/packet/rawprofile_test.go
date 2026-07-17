package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// prependIP4 builds a minimal 20-byte IPv4 header in front of l4, imitating what
// a Linux raw ip4 socket hands back on read (header included).
func prependIP4(src, dst net.IP, proto int, l4 []byte) []byte {
	h := make([]byte, 20+len(l4))
	h[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))
	h[8] = 64 // TTL
	h[9] = byte(proto)
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	copy(h[20:], l4)
	return h
}

var (
	testSrc = net.IPv4(10, 20, 0, 1)
	testDst = net.IPv4(10, 20, 0, 2)
)

func TestRawProfileRoundTrip(t *testing.T) {
	// A payload with a leading 0x4X byte would, if the IP header were mis-parsed,
	// be corrupted — so this doubles as a regression guard for the strip logic.
	payloads := [][]byte{
		[]byte("the-sealed-aead-frame-goes-here-0123456789"),
		{0x45, 0x00, 0x11, 0x22, 0x33}, // looks like the start of an IPv4 header
		bytes.Repeat([]byte{0xAA}, 1),  // 1-byte payload
	}
	for name := range rawProfiles {
		proto, _ := rawProtoFor(name)
		for i, pl := range payloads {
			for _, client := range []bool{true, false} {
				l4 := rawEncap(name, pl, testSrc, testDst, client, 0x1234, uint32(i+1), 0)
				// Two reads must both round-trip: one where the kernel included
				// the outer IPv4 header, and one where it did not (both happen in
				// the wild depending on platform).
				withIP := prependIP4(testSrc, testDst, proto, l4)
				for _, variant := range []struct {
					name string
					pkt  []byte
				}{{"with-ip", withIP}, {"no-ip", l4}} {
					got, ok := rawDecap(name, proto, variant.pkt)
					if !ok {
						t.Fatalf("profile %s payload#%d client=%v %s: decap failed", name, i, client, variant.name)
					}
					if !bytes.Equal(got, pl) {
						t.Fatalf("profile %s payload#%d client=%v %s: got %x want %x", name, i, client, variant.name, got, pl)
					}
				}
			}
		}
	}
}

func TestRawProtoNumbers(t *testing.T) {
	want := map[string]int{"bip": 253, "ipip": 4, "gre": 47, "icmp": 1, "udp": 17, "tcp": 6}
	for name, n := range want {
		got, ok := rawProtoFor(name)
		if !ok || got != n {
			t.Errorf("proto(%s) = %d,%v want %d", name, got, ok, n)
		}
	}
	if _, ok := rawProtoFor("nope"); ok {
		t.Error("rawProtoFor accepted an unknown profile")
	}
}

func TestRawEffProto(t *testing.T) {
	// bip may take any 1..255; everything else keeps its native number.
	cases := []struct {
		profile   string
		override  int
		want      int
		wantOK    bool
	}{
		{"bip", 0, 253, true},    // unset -> native
		{"bip", 58, 58, true},    // ICMPv6 override
		{"bip", 255, 255, true},  // top of range
		{"bip", 300, 253, true},  // out of range -> native
		{"bip", -1, 253, true},   // negative -> native
		{"gre", 58, 47, true},    // override ignored for a headered profile
		{"udp", 99, 17, true},    // ignored
		{"nope", 58, 0, false},   // unknown profile
	}
	for _, c := range cases {
		got, ok := rawEffProto(c.profile, c.override)
		if got != c.want || ok != c.wantOK {
			t.Errorf("rawEffProto(%q,%d) = %d,%v want %d,%v", c.profile, c.override, got, ok, c.want, c.wantOK)
		}
	}
}

func TestRawBipCustomProtoRoundTrip(t *testing.T) {
	// A bip carrier on a custom protocol number (e.g. 58) stays header-less and must
	// round-trip: the outer IPv4's protocol byte carries the custom number, and decap
	// keys the header stripping off the profile (bip -> bare), not the number.
	pl := []byte("the-sealed-aead-frame")
	const custom = 58
	l4 := rawEncap("bip", pl, testSrc, testDst, true, 0, 0, 0) // bip is bare -> l4 == pl
	if !bytes.Equal(l4, pl) {
		t.Fatalf("bip added a header: %x", l4)
	}
	for _, variant := range []struct {
		name string
		pkt  []byte
	}{
		{"with-ip", prependIP4(testSrc, testDst, custom, l4)}, // kernel included the proto-58 IPv4 header
		{"no-ip", l4},
	} {
		got, ok := rawDecap("bip", custom, variant.pkt)
		if !ok {
			t.Fatalf("%s: bip/proto-%d decap failed", variant.name, custom)
		}
		if !bytes.Equal(got, pl) {
			t.Fatalf("%s: got %x want %x", variant.name, got, pl)
		}
	}
}

func TestRawBipIpipHaveNoL4Header(t *testing.T) {
	pl := []byte("payload")
	for _, name := range []string{"bip", "ipip"} {
		l4 := rawEncap(name, pl, testSrc, testDst, true, 0, 0, 0)
		if !bytes.Equal(l4, pl) {
			t.Errorf("profile %s added a header: %x", name, l4)
		}
	}
}

func TestRawChecksumsValid(t *testing.T) {
	pl := bytes.Repeat([]byte{0x5A}, 41) // odd length exercises the checksum padding
	// ICMP: recomputing the internet checksum over the whole L4 (checksum field
	// in place) must fold to zero.
	icmp := rawEncap("icmp", pl, testSrc, testDst, true, 0xABCD, 7, 0)
	if s := onesComplementSum(icmp); s != 0 {
		t.Errorf("icmp checksum invalid: fold = %#x", s)
	}
	// TCP: pseudo-header checksum must fold to zero.
	tcp := rawEncap("tcp", pl, testSrc, testDst, true, 0, 99, 0)
	if s := l4Checksum(testSrc, testDst, protoTCP, tcp); s != 0 {
		t.Errorf("tcp checksum invalid: fold = %#x", s)
	}
	// UDP: folds to zero (0x0000 and 0xffff are equivalent in one's complement).
	udp := rawEncap("udp", pl, testSrc, testDst, true, 0, 99, 0)
	if s := l4Checksum(testSrc, testDst, protoUDP, udp); s != 0 && s != 0xffff {
		t.Errorf("udp checksum invalid: fold = %#x", s)
	}
}

func TestRawICMPDirection(t *testing.T) {
	req := rawEncap("icmp", []byte("x"), testSrc, testDst, true, 1, 1, 0)
	if req[0] != 8 {
		t.Errorf("client ICMP type = %d, want 8 (echo request)", req[0])
	}
	rep := rawEncap("icmp", []byte("x"), testSrc, testDst, false, 1, 1, 0)
	if rep[0] != 0 {
		t.Errorf("server ICMP type = %d, want 0 (echo reply)", rep[0])
	}
}

func TestRawTCPLiveFlowFields(t *testing.T) {
	// The tcp profile must carry the caller's sequence AND a non-zero acknowledgement plus a
	// realistic window — an ACK-flagged segment with ack=0 / window=0xffff reads as forged.
	tcp := rawEncap("tcp", []byte("data"), testSrc, testDst, true, 0, 0x11223344, 0x55667788)
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 0x11223344 {
		t.Errorf("tcp seq = %#x, want %#x", got, 0x11223344)
	}
	if got := binary.BigEndian.Uint32(tcp[8:12]); got != 0x55667788 {
		t.Errorf("tcp ack = %#x, want the passed non-zero ack (ack=0 with the ACK flag is a forged-segment tell)", got)
	}
	if got := binary.BigEndian.Uint16(tcp[14:16]); got != rawTCPWindow {
		t.Errorf("tcp window = %#x, want realistic %#x", got, rawTCPWindow)
	}
	if tcp[13] != 0x18 {
		t.Errorf("tcp flags = %#x, want PSH|ACK (0x18)", tcp[13])
	}
}

func TestRawDecapRejectsShortCarrier(t *testing.T) {
	// Profiles with a carrier header must reject a packet too short to hold it.
	if _, ok := rawDecap("gre", protoGRE, []byte{0x00, 0x00}); ok {
		t.Error("gre decap accepted fewer than 4 header bytes")
	}
	if _, ok := rawDecap("icmp", protoICMP, []byte{0x08, 0x00}); ok {
		t.Error("icmp decap accepted fewer than 8 header bytes")
	}
	if _, ok := rawDecap("tcp", protoTCP, bytes.Repeat([]byte{0x00}, 10)); ok {
		t.Error("tcp decap accepted fewer than 20 header bytes")
	}
	// bip/ipip carry no header: any bytes are a valid (opaque) sealed frame.
	if _, ok := rawDecap("bip", protoBIP, []byte{0x01, 0x02}); !ok {
		t.Error("bip decap should accept any bytes as the frame")
	}
	// A real IPv4-wrapped GRE packet with no room for the GRE header is rejected.
	if _, ok := rawDecap("gre", protoGRE, prependIP4(testSrc, testDst, protoGRE, []byte{0x00})); ok {
		t.Error("gre decap accepted an IPv4 packet too short for its GRE header")
	}
}
