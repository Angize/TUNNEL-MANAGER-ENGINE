package packet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/crypto"
)

func mustSealer(t *testing.T, psk string) Sealer {
	t.Helper()
	s, err := crypto.NewSealer(crypto.CipherChaCha, psk)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestObfsSealOpenRoundTrip(t *testing.T) {
	s := mustSealer(t, "roundtrip-psk-123456")
	for _, pt := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte{0xAB}, 1400)} {
		for _, typ := range []byte{typeData, typePing, typePong} {
			sealed, err := obfsSeal(s, typ, pt, padMaxFor(typ))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			gotTyp, gotPt, err := obfsOpen(s, sealed)
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
	// must differ (random nonce), and no fixed leading byte like the old magic.
	s := mustSealer(t, "prefix-psk-abcdefabcdef")
	a, _ := obfsSeal(s, typeData, []byte("hello"), 0)
	b, _ := obfsSeal(s, typeData, []byte("hello"), 0)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of identical plaintext are identical (nonce reuse?)")
	}
	if a[0] == magic && b[0] == magic {
		t.Fatal("leading byte equals the legacy magic on both — that is a signature")
	}
}

func TestObfsTamperFails(t *testing.T) {
	s := mustSealer(t, "tamper-psk-0987654321")
	sealed, _ := obfsSeal(s, typeData, []byte("secret payload"), 0)
	sealed[len(sealed)-1] ^= 0xFF // flip a tag byte
	if _, _, err := obfsOpen(s, sealed); err == nil {
		t.Fatal("tampered frame opened without error")
	}
}

func TestObfsWrongPSKFails(t *testing.T) {
	sealed, _ := obfsSeal(mustSealer(t, "psk-alpha-1111111111"), typeData, []byte("hi"), 0)
	if _, _, err := obfsOpen(mustSealer(t, "psk-beta-22222222222"), sealed); err == nil {
		t.Fatal("frame opened under the wrong PSK (no probe resistance)")
	}
}

func TestObfsPaddingVaries(t *testing.T) {
	// Control frames get random padding, so sealed sizes should not be constant.
	s := mustSealer(t, "pad-psk-777777777777")
	sizes := map[int]bool{}
	for i := 0; i < 64; i++ {
		sealed, _ := obfsSeal(s, typePing, nil, obfsCtrlPadMax)
		sizes[len(sealed)] = true
	}
	if len(sizes) < 4 {
		t.Fatalf("padding not varying: only %d distinct sizes over 64 frames", len(sizes))
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
