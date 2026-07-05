package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSealOpenRoundTripAllCiphers(t *testing.T) {
	pt := []byte("the quick brown fox jumps over the lazy dog")
	for _, name := range Supported {
		s, err := NewSealer(name, "correct horse battery staple")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Name != name {
			t.Fatalf("resolved name %q != %q", s.Name, name)
		}
		ct, err := s.Seal(pt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Contains(ct, pt) {
			t.Fatalf("%s: ciphertext leaks plaintext", name)
		}
		_, _, got, err := s.Open(ct)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("%s: round trip mismatch", name)
		}
	}
}

func TestResolveCipher(t *testing.T) {
	cases := map[string]string{
		"":            CipherAES256,
		"auto":        CipherAES256,
		"AES-256-GCM": CipherAES256,
		"aes128":      CipherAES128,
		"chacha":      CipherChaCha,
		"xchacha20":   CipherXChaCha,
	}
	for in, want := range cases {
		if got := ResolveCipher(in); got != want {
			t.Fatalf("ResolveCipher(%q)=%q want %q", in, got, want)
		}
	}
	if _, err := NewSealer("blowfish", "k"); err == nil {
		t.Fatal("unknown cipher should error")
	}
}

func TestNonceIsFresh(t *testing.T) {
	s, _ := NewSealer("chacha20-poly1305", "k")
	a, _ := s.Seal([]byte("x"))
	b, _ := s.Seal([]byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("nonce reused: identical ciphertext for identical plaintext")
	}
}

func TestWrongKeyFails(t *testing.T) {
	s1, _ := NewSealer("aes-256-gcm", "key-one")
	s2, _ := NewSealer("aes-256-gcm", "key-two")
	ct, _ := s1.Seal([]byte("secret"))
	if _, _, _, err := s2.Open(ct); err == nil {
		t.Fatal("open with wrong key should fail")
	}
}

func TestCipherMismatchFails(t *testing.T) {
	// same psk, different AEAD -> must not interoperate
	a, _ := NewSealer("aes-256-gcm", "same-psk")
	c, _ := NewSealer("chacha20-poly1305", "same-psk")
	ct, _ := a.Seal([]byte("secret"))
	if _, _, _, err := c.Open(ct); err == nil {
		t.Fatal("aes ciphertext opened by chacha should fail")
	}
}

func TestTamperFails(t *testing.T) {
	s, _ := NewSealer("xchacha20-poly1305", "k")
	ct, _ := s.Seal([]byte("secret"))
	ct[len(ct)-1] ^= 0x01 // flip a tag bit
	if _, _, _, err := s.Open(ct); err == nil {
		t.Fatal("open of tampered ciphertext should fail")
	}
}

// TestSeqIncrementsMonotonically checks the counter nonce advances by exactly 1
// per Seal so it can serve as the anti-replay sequence number, and never reuses
// a value within a process.
func TestSeqIncrementsMonotonically(t *testing.T) {
	for _, name := range Supported {
		s, _ := NewSealer(name, "seq-psk")
		var prev uint64
		seen := map[uint64]bool{}
		for i := 0; i < 1000; i++ {
			ct, _ := s.Seal([]byte("d"))
			_, seq, _, err := s.Open(ct)
			if err != nil {
				t.Fatalf("%s: open: %v", name, err)
			}
			if seen[seq] {
				t.Fatalf("%s: seq %d reused (nonce reuse!)", name, seq)
			}
			seen[seq] = true
			if i > 0 && seq != prev+1 {
				t.Fatalf("%s: seq jumped %d -> %d", name, prev, seq)
			}
			prev = seq
		}
	}
}

// TestSessionDiffersPerProcess checks two sealers built from the SAME psk pick
// different random nonce prefixes, so their nonce spaces don't collide (this is
// what keeps the two tunnel directions, which share a key, from reusing nonces).
func TestSessionDiffersPerProcess(t *testing.T) {
	a, _ := NewSealer("aes-256-gcm", "same-psk-both-ends")
	b, _ := NewSealer("aes-256-gcm", "same-psk-both-ends")
	ca, _ := a.Seal([]byte("x"))
	cb, _ := b.Seal([]byte("x"))
	// Both are the first Seal (seq 1); if the prefixes matched the whole nonce
	// would match. The leading NonceSize-8 bytes are the prefix.
	ns := a.aead.NonceSize()
	if bytes.Equal(ca[:ns-8], cb[:ns-8]) {
		t.Fatal("two sealers share a session prefix (2^-32 fluke or a bug)")
	}
	sa, _, _, _ := a.Open(ca)
	sb, _, _, _ := b.Open(cb)
	if sa == sb {
		t.Fatal("distinct sealers report the same session id")
	}
}

// TestOpenReturnsSeqFromNonce checks Open surfaces exactly the counter that Seal
// embedded, independent of ciphertext content.
func TestOpenReturnsSeqFromNonce(t *testing.T) {
	s, _ := NewSealer("aes-128-gcm", "k")
	ct, _ := s.Seal([]byte("hello"))
	ns := s.aead.NonceSize()
	wantSeq := binary.BigEndian.Uint64(ct[ns-8 : ns])
	_, seq, _, err := s.Open(ct)
	if err != nil {
		t.Fatal(err)
	}
	if seq != wantSeq {
		t.Fatalf("Open seq %d != nonce seq %d", seq, wantSeq)
	}
}
