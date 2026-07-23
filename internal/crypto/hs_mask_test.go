package crypto

import "testing"

// The masked handshake must be HandshakeSize bytes and still round-trip: Init->ParseInit and
// Resp->ParseResp recover the exact public keys, and a wrong PSK fails after unmasking.
func TestHandshakeMaskRoundTrip(t *testing.T) {
	psk := "a-preshared-key"
	ci, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	msg1 := InitMsg(psk, ci)
	if len(msg1) != HandshakeSize {
		t.Fatalf("init length %d, want %d", len(msg1), HandshakeSize)
	}
	eInit, err := ParseInit(psk, msg1)
	if err != nil {
		t.Fatalf("ParseInit: %v", err)
	}
	if eInit != ci.Pub {
		t.Fatal("init public key did not round-trip through the mask")
	}
	if _, err := ParseInit("wrong-psk", msg1); err == nil {
		t.Fatal("a wrong PSK unmasked to a valid init (MAC should fail)")
	}

	sr, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	msg2 := RespMsg(psk, ci.Pub, sr)
	if len(msg2) != HandshakeSize {
		t.Fatalf("resp length %d, want %d", len(msg2), HandshakeSize)
	}
	eResp, err := ParseResp(psk, ci.Pub, msg2)
	if err != nil {
		t.Fatalf("ParseResp: %v", err)
	}
	if eResp != sr.Pub {
		t.Fatal("resp public key did not round-trip through the mask")
	}
}

// A raw X25519 public value is a canonical curve point, so the top bit of its last wire byte (bit 255)
// is ALWAYS 0 — a bias a passive classifier can aggregate per-IP. After masking, that same on-wire
// position must vary ~uniformly across handshakes, proving the point structure is hidden.
func TestHandshakeWireHidesPointBias(t *testing.T) {
	const N = 3000
	psk := "psk"
	highSet := 0
	for i := 0; i < N; i++ {
		e, err := GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		msg := InitMsg(psk, e)
		// last byte of the 32-byte public-value region, which carries bit 255 (0x80) of the point.
		if msg[hsNonceLen+ephPubLen-1]&0x80 != 0 {
			highSet++
		}
	}
	// Raw (unmasked) would give highSet == 0. Masked should sit near N/2; allow a wide band.
	if highSet < N/4 || highSet > 3*N/4 {
		t.Fatalf("masked high bit set in %d/%d handshakes — not uniform (raw point leaking?)", highSet, N)
	}
}
