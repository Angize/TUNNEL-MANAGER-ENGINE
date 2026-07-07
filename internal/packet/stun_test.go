//go:build linux

package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildSTUN must produce a structurally valid STUN message (magic cookie, a
// 4-byte-aligned message length that covers exactly one attribute) and parseSTUN
// must recover the exact payload for any length — including ones not a multiple of
// four, where the attribute is padded on the wire.
func TestSTUNRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 5, 41, 180, 1400} {
		payload := bytes.Repeat([]byte{0xC3}, n)
		msg := buildSTUN(payload)

		if len(msg) < 24 {
			t.Fatalf("n=%d: STUN message too short: %d", n, len(msg))
		}
		if binary.BigEndian.Uint32(msg[4:8]) != stunMagic {
			t.Fatalf("n=%d: missing magic cookie", n)
		}
		msgLen := int(binary.BigEndian.Uint16(msg[2:4]))
		if msgLen%4 != 0 {
			t.Fatalf("n=%d: STUN message length %d is not 4-byte aligned", n, msgLen)
		}
		if 20+msgLen != len(msg) {
			t.Fatalf("n=%d: message length %d does not match body %d", n, msgLen, len(msg)-20)
		}
		if got := binary.BigEndian.Uint16(msg[20:22]); got != stunAttrType {
			t.Fatalf("n=%d: attribute type = %#x want %#x", n, got, stunAttrType)
		}
		if got := int(binary.BigEndian.Uint16(msg[22:24])); got != n {
			t.Fatalf("n=%d: attribute length = %d want %d", n, got, n)
		}

		got, ok := parseSTUN(msg)
		if !ok {
			t.Fatalf("n=%d: parseSTUN rejected our own message", n)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("n=%d: parseSTUN returned %x want %x", n, got, payload)
		}
	}
}

// A datagram without the magic cookie (or too short to hold the header+attribute)
// must be rejected before the AEAD ever sees it.
func TestSTUNRejectsNonSTUN(t *testing.T) {
	if _, ok := parseSTUN(bytes.Repeat([]byte{0x00}, 24)); ok {
		t.Error("parseSTUN accepted a datagram with no magic cookie")
	}
	if _, ok := parseSTUN(bytes.Repeat([]byte{0x00}, 10)); ok {
		t.Error("parseSTUN accepted a datagram too short for the STUN + attribute header")
	}
	// A valid header whose attribute length runs past the buffer must be rejected.
	msg := buildSTUN([]byte("hello"))
	binary.BigEndian.PutUint16(msg[22:24], uint16(len(msg))) // absurd attribute length
	if _, ok := parseSTUN(msg); ok {
		t.Error("parseSTUN accepted an attribute length past the buffer end")
	}
}
