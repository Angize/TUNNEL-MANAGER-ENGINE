package dnstun

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestNewCodecZoneNormalization(t *testing.T) {
	for _, in := range []string{"t.example.com", "t.example.com.", "T.Example.Com", " t.example.com "} {
		c, err := NewCodec(in)
		if err != nil {
			t.Fatalf("NewCodec(%q): %v", in, err)
		}
		if c.Zone() != "t.example.com." {
			t.Fatalf("NewCodec(%q) zone = %q, want t.example.com.", in, c.Zone())
		}
	}
	for _, bad := range []string{"", "   ", ".."} {
		if _, err := NewCodec(bad); err == nil {
			t.Errorf("NewCodec(%q) accepted a malformed zone", bad)
		}
	}
}

func TestNameRoundTrip(t *testing.T) {
	c, err := NewCodec("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxUpstream() < 16 {
		t.Fatalf("MaxUpstream = %d, implausibly small", c.MaxUpstream())
	}
	for _, size := range []int{0, 1, 5, 31, c.MaxUpstream() - 1, c.MaxUpstream()} {
		if size < 0 {
			continue
		}
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		name, err := c.EncodeName(data, newNonce())
		if err != nil {
			t.Fatalf("EncodeName(%d bytes): %v", size, err)
		}
		if wire := zoneWireLen(strings.ToLower(name)); wire > maxName {
			t.Fatalf("EncodeName(%d) produced a %d-byte name > %d limit", size, wire, maxName)
		}
		got, err := c.DecodeName(name)
		if err != nil {
			t.Fatalf("DecodeName(%d bytes): %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch at %d bytes: got %x want %x", size, got, data)
		}
	}
}

func TestNameOverCapacityRejected(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	if _, err := c.EncodeName(make([]byte, c.MaxUpstream()+1), newNonce()); err == nil {
		t.Fatal("EncodeName accepted an over-capacity datagram")
	}
}

func TestEncodeNameRejectsBadNonce(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	if _, err := c.EncodeName([]byte{1, 2, 3}, ""); err == nil {
		t.Fatal("EncodeName accepted an empty nonce")
	}
	if _, err := c.EncodeName([]byte{1, 2, 3}, strings.Repeat("a", maxLabel+1)); err == nil {
		t.Fatal("EncodeName accepted an over-long nonce")
	}
}

func TestNonceMakesEveryNameUnique(t *testing.T) {
	// The whole point of the nonce: identical payloads (and the empty poll) must still yield DISTINCT
	// query names every call, so a recursive resolver can never cache or coalesce them.
	c, _ := NewCodec("t.example.com")
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		name, err := c.EncodeName(nil, newNonce()) // the idle poll: same (empty) payload every time
		if err != nil {
			t.Fatal(err)
		}
		if seen[name] {
			t.Fatalf("duplicate poll name %q — resolver could cache/coalesce it", name)
		}
		seen[name] = true
		// A nonce-only poll name must still decode to zero upstream bytes.
		got, derr := c.DecodeName(name)
		if derr != nil || len(got) != 0 {
			t.Fatalf("poll name %q decoded to %x (err %v), want empty", name, got, derr)
		}
	}
}

func TestDecodeName0x20CaseRandomization(t *testing.T) {
	// A recursive resolver may randomize the case of the query name (0x20 encoding). Decoding must
	// still recover the exact bytes, because we lowercase before base32-decoding.
	c, _ := NewCodec("t.example.com")
	data := make([]byte, 40)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	name, _ := c.EncodeName(data, newNonce())

	// Flip case on alternating characters, as a 0x20-randomizing resolver would.
	rc := []rune(name)
	for i := range rc {
		if i%2 == 0 {
			rc[i] = []rune(strings.ToUpper(string(rc[i])))[0]
		}
	}
	got, err := c.DecodeName(string(rc))
	if err != nil {
		t.Fatalf("DecodeName on case-randomized name: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("0x20 case randomization corrupted the decoded datagram")
	}
}

func TestDecodeNameRejectsForeignZone(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	if _, err := c.DecodeName("abcd.evil.example.net."); err == nil {
		t.Fatal("DecodeName accepted a name outside the zone")
	}
}

func TestDecodeNameRejectsSharedSuffixLabel(t *testing.T) {
	// "abt.example.com" shares the literal suffix "t.example.com" but "abt" is a single foreign
	// label, not "ab" + the zone. A plain HasSuffix check would accept it and mis-parse "ab" as
	// upstream data; the label-boundary check must reject it.
	c, _ := NewCodec("t.example.com")
	if _, err := c.DecodeName("abt.example.com."); err == nil {
		t.Fatal("DecodeName accepted a name whose last label merely ends with the zone")
	}
}

func TestDecodeBareZoneIsEmpty(t *testing.T) {
	// A poll query for the bare zone (no data labels) is valid and carries zero upstream bytes.
	c, _ := NewCodec("t.example.com")
	got, err := c.DecodeName("t.example.com.")
	if err != nil {
		t.Fatalf("DecodeName(bare zone): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("bare-zone query decoded to %d bytes, want 0", len(got))
	}
}

func TestTXTRoundTrip(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	for _, size := range []int{0, 1, 100, 255, 300} {
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		got := c.DecodeTXT(c.EncodeTXT(data))
		if size == 0 {
			if len(got) != 0 {
				t.Fatalf("TXT round-trip of empty got %d bytes", len(got))
			}
			continue
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("TXT round-trip mismatch at %d bytes", size)
		}
	}
}
