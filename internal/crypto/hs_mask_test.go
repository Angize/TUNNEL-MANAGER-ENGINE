package crypto

import (
	"bytes"
	"io"
	"testing"
)

// The masked+padded handshake must round-trip: Init->ParseInit and Resp->ParseResp recover the exact
// public keys, and a wrong PSK fails after unmasking. Messages are at least HandshakeCoreSize bytes.
func TestHandshakeMaskRoundTrip(t *testing.T) {
	psk := "a-preshared-key"
	ci, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	msg1 := InitMsg(psk, ci)
	if len(msg1) < HandshakeCoreSize {
		t.Fatalf("init length %d, want >= %d", len(msg1), HandshakeCoreSize)
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
		// last byte of the 32-byte public-value region (which carries bit 255 of the point).
		if msg[hsNonceLen+hsPadLenLen+ephPubLen-1]&0x80 != 0 {
			highSet++
		}
	}
	if highSet < N/4 || highSet > 3*N/4 {
		t.Fatalf("masked high bit set in %d/%d handshakes — not uniform (raw point leaking?)", highSet, N)
	}
}

// The message LENGTH must vary across handshakes (random pad), so the opening has no fixed byte-count
// signature to key on. Require many distinct sizes and a wide spread over many handshakes.
func TestHandshakeSizeVaries(t *testing.T) {
	const N = 2000
	psk := "psk"
	sizes := map[int]bool{}
	min, max := 1<<30, 0
	for i := 0; i < N; i++ {
		e, err := GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		n := len(InitMsg(psk, e))
		if n < HandshakeCoreSize {
			t.Fatalf("message %d below core size %d", n, HandshakeCoreSize)
		}
		sizes[n] = true
		if n < min {
			min = n
		}
		if n > max {
			max = n
		}
	}
	if len(sizes) < 50 {
		t.Fatalf("only %d distinct handshake sizes over %d — pad is not varying", len(sizes), N)
	}
	if max-min < 100 {
		t.Fatalf("size spread only %d bytes (min %d, max %d) — pad too narrow", max-min, min, max)
	}
}

// ReadHandshake must recover the fixed core from a STREAM carrying core||pad, consuming the trailing
// pad so the next read starts cleanly, and the recovered core must ParseInit to the same key.
func TestReadHandshakeStream(t *testing.T) {
	psk := "psk"
	e, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	msg := InitMsg(psk, e)
	const trailer = "NEXT-FRAME-BYTES"
	stream := bytes.NewReader(append(append([]byte{}, msg...), trailer...))
	core, err := ReadHandshake(stream, psk)
	if err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	got, err := ParseInit(psk, core)
	if err != nil {
		t.Fatalf("ParseInit after ReadHandshake: %v", err)
	}
	if got != e.Pub {
		t.Fatal("public key mismatch after stream read")
	}
	// The pad must have been fully consumed: what's left is exactly the trailer.
	rest := make([]byte, len(trailer))
	if _, err := io.ReadFull(stream, rest); err != nil {
		t.Fatalf("read trailer after handshake: %v", err)
	}
	if string(rest) != trailer {
		t.Fatalf("pad not fully consumed; remaining %q want %q", rest, trailer)
	}
}
