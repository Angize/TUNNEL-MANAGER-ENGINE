// Package crypto provides the AEAD sealing used by the bip carrier.
//
// Design: a single symmetric key is derived from the pre-shared key with a
// domain-separated SHA-256 (32 bytes -> AES-256). Every sealed message carries
// its own random 12-byte GCM nonce, prepended to the ciphertext. AES-256-GCM
// is chosen for the first slice because it is stdlib-only (crypto/aes +
// crypto/cipher) and hardware-accelerated on any AES-NI CPU; chacha20-poly1305
// can be added later once we vendor golang.org/x/crypto for non-AES-NI hosts.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Sealer seals and opens packet payloads with AES-256-GCM.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer derives the key from psk and returns a ready Sealer.
func NewSealer(psk string) (*Sealer, error) {
	key := sha256.Sum256([]byte("tnl-bip-aead|v1|" + psk))
	block, err := aes.NewCipher(key[:]) // 32-byte key => AES-256
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Overhead is the number of bytes Seal adds to a plaintext (nonce + tag).
func (s *Sealer) Overhead() int {
	return s.aead.NonceSize() + s.aead.Overhead()
}

// Seal returns nonce||ciphertext. It never reuses a nonce (random per call).
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends the ciphertext to nonce, so the result is nonce||ct||tag.
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal. It returns an error on any authentication failure.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("sealed payload too short")
	}
	return s.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
}
