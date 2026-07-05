package crypto

import (
	"bytes"
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
		got, err := s.Open(ct)
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
		"":                   CipherAES256,
		"auto":               CipherAES256,
		"AES-256-GCM":        CipherAES256,
		"aes128":             CipherAES128,
		"chacha":             CipherChaCha,
		"xchacha20":          CipherXChaCha,
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
	if _, err := s2.Open(ct); err == nil {
		t.Fatal("open with wrong key should fail")
	}
}

func TestCipherMismatchFails(t *testing.T) {
	// same psk, different AEAD -> must not interoperate
	a, _ := NewSealer("aes-256-gcm", "same-psk")
	c, _ := NewSealer("chacha20-poly1305", "same-psk")
	ct, _ := a.Seal([]byte("secret"))
	if _, err := c.Open(ct); err == nil {
		t.Fatal("aes ciphertext opened by chacha should fail")
	}
}

func TestTamperFails(t *testing.T) {
	s, _ := NewSealer("xchacha20-poly1305", "k")
	ct, _ := s.Seal([]byte("secret"))
	ct[len(ct)-1] ^= 0x01 // flip a tag bit
	if _, err := s.Open(ct); err == nil {
		t.Fatal("open of tampered ciphertext should fail")
	}
}
