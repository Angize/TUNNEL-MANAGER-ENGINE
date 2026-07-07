package packet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

// mustPair returns the two ends of a tunnel (client seals c→s, server opens it).
func mustPair(t *testing.T, psk string) (client, server Sealer) {
	t.Helper()
	c, err := crypto.NewSealer(crypto.CipherChaCha, psk, true)
	if err != nil {
		t.Fatalf("client NewSealer: %v", err)
	}
	s, err := crypto.NewSealer(crypto.CipherChaCha, psk, false)
	if err != nil {
		t.Fatalf("server NewSealer: %v", err)
	}
	return c, s
}

func TestObfsSealOpenRoundTrip(t *testing.T) {
	c, s := mustPair(t, "roundtrip-psk-123456")
	for _, pt := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte{0xAB}, 1400)} {
		for _, typ := range []byte{typeData, typePing, typePong} {
			sealed, err := obfsSeal(c, typ, pt, padMaxFor(typ))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			gotTyp, _, _, gotPt, err := obfsOpen(s, sealed)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if gotTyp != typ {
				t.Fatalf("type: got %d want %d", gotTyp, typ)
			}
			if !bytes.Equal(gotPt, pt) {
				t.Fatalf("payload mismatch: got %x want %x", gotPt, pt)
			}
		}
	}
}

func TestObfsNoConstantPrefix(t *testing.T) {
	// The whole sealed frame must look random: sealing the SAME plaintext twice
	// must differ (advancing nonce + fresh mask salt), and no fixed leading byte.
	c, _ := mustPair(t, "prefix-psk-abcdefabcdef")
	a, _ := obfsSeal(c, typeData, []byte("hello"), 0)
	b, _ := obfsSeal(c, typeData, []byte("hello"), 0)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of identical plaintext are identical (nonce/salt reuse?)")
	}
	if a[0] == magic && b[0] == magic {
		t.Fatal("leading byte equals the legacy magic on both — that is a signature")
	}
}

func TestObfsTamperFails(t *testing.T) {
	c, s := mustPair(t, "tamper-psk-0987654321")
	sealed, _ := obfsSeal(c, typeData, []byte("secret payload"), 0)
	sealed[len(sealed)-1] ^= 0xFF // flip a tag byte
	if _, _, _, _, err := obfsOpen(s, sealed); err == nil {
		t.Fatal("tampered frame opened without error")
	}
}

func TestObfsWrongPSKFails(t *testing.T) {
	cA, _ := mustPair(t, "psk-alpha-1111111111")
	_, sB := mustPair(t, "psk-beta-22222222222")
	sealed, _ := obfsSeal(cA, typeData, []byte("hi"), 0)
	if _, _, _, _, err := obfsOpen(sB, sealed); err == nil {
		t.Fatal("frame opened under the wrong PSK (no probe resistance)")
	}
}

func TestObfsPaddingVaries(t *testing.T) {
	// Control frames get random padding, so sealed sizes should not be constant.
	c, _ := mustPair(t, "pad-psk-777777777777")
	sizes := map[int]bool{}
	for i := 0; i < 64; i++ {
		sealed, _ := obfsSeal(c, typePing, nil, obfsCtrlPadMax)
		sizes[len(sealed)] = true
	}
	if len(sizes) < 4 {
		t.Fatalf("padding not varying: only %d distinct sizes over 64 frames", len(sizes))
	}
}

// TestObfsOpenReportsSeq checks obfsOpen surfaces the sender's monotonically
// increasing sequence number so the carrier can feed it to the replay window.
func TestObfsOpenReportsSeq(t *testing.T) {
	c, s := mustPair(t, "seq-obfs-psk-000000")
	var prev uint64
	for i := 0; i < 50; i++ {
		sealed, _ := obfsSeal(c, typeData, []byte("d"), 0)
		_, _, seq, _, err := obfsOpen(s, sealed)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && seq != prev+1 {
			t.Fatalf("seq not monotonic: %d -> %d", prev, seq)
		}
		prev = seq
	}
}

func TestObfsLengthKeystreamSymmetry(t *testing.T) {
	// Masking a length with the sender's keystream and unmasking with a reader
	// keystream seeded by the SAME salt must recover the original length, and
	// the mask must actually change the bytes.
	psk := "ks-psk-555555555555"
	salt := bytes.Repeat([]byte{0x11}, obfsSaltLen)
	w, err := newObfsStream(psk, salt)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	r, _ := newObfsStream(psk, salt)
	for _, L := range []uint16{1, 42, 1500, 65535} {
		var lb, masked, unmasked [2]byte
		binary.BigEndian.PutUint16(lb[:], L)
		w.XORKeyStream(masked[:], lb[:])
		if masked == lb {
			t.Fatalf("length %d not masked", L)
		}
		r.XORKeyStream(unmasked[:], masked[:])
		if binary.BigEndian.Uint16(unmasked[:]) != L {
			t.Fatalf("unmask mismatch for %d", L)
		}
	}
}

// TestRandUintBoundsAndUniformity checks the rejection-sampling helper stays in
// range and is roughly uniform (no modulo bias toward the low end).
func TestRandUintBoundsAndUniformity(t *testing.T) {
	if v, _ := randUint(0); v != 0 {
		t.Fatalf("randUint(0) = %d, want 0", v)
	}
	const max = 64
	counts := make([]int, max+1)
	const N = 200000
	for i := 0; i < N; i++ {
		v, err := randUint(max)
		if err != nil {
			t.Fatal(err)
		}
		if v < 0 || v > max {
			t.Fatalf("randUint(%d) out of range: %d", max, v)
		}
		counts[v]++
	}
	// Every bucket should be populated and near the expected mean; a modulo-biased
	// generator would leave the top buckets measurably light. Allow a wide band.
	exp := float64(N) / float64(max+1)
	for i, c := range counts {
		if float64(c) < exp*0.7 || float64(c) > exp*1.3 {
			t.Fatalf("bucket %d skewed: got %d, expected ~%.0f (bias?)", i, c, exp)
		}
	}
}
