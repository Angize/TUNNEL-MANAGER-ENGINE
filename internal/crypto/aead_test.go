package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := NewSealer("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("the quick brown fox jumps over the lazy dog")
	ct, err := s.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := s.Open(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch: %q != %q", got, pt)
	}
}

func TestNonceIsFresh(t *testing.T) {
	s, _ := NewSealer("k")
	a, _ := s.Seal([]byte("x"))
	b, _ := s.Seal([]byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("nonce reused: identical ciphertext for identical plaintext")
	}
}

func TestWrongKeyFails(t *testing.T) {
	s1, _ := NewSealer("key-one")
	s2, _ := NewSealer("key-two")
	ct, _ := s1.Seal([]byte("secret"))
	if _, err := s2.Open(ct); err == nil {
		t.Fatal("open with wrong key should fail")
	}
}

func TestTamperFails(t *testing.T) {
	s, _ := NewSealer("k")
	ct, _ := s.Seal([]byte("secret"))
	ct[len(ct)-1] ^= 0x01 // flip a tag bit
	if _, err := s.Open(ct); err == nil {
		t.Fatal("open of tampered ciphertext should fail")
	}
}
