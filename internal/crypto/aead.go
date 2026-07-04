// Package crypto provides the AEAD sealing used by the bip carrier.
//
// Two AEADs are supported and selected by name: AES-256-GCM (stdlib, fastest on
// AES-NI hosts) and ChaCha20-Poly1305 (constant-time in software, faster on
// hosts without AES acceleration such as many ARM boards). Both derive their
// key from the pre-shared key with a domain-separated SHA-256, and every sealed
// message carries its own random nonce prepended to the ciphertext.
//
// IMPORTANT: both ends of a tunnel MUST use the same cipher — an AEAD sealed
// with AES-GCM cannot be opened with ChaCha20. "auto" therefore resolves to a
// single deterministic choice (aes-256-gcm) rather than a per-host, CPU-based
// one, so two nodes of different architectures always agree. Pick
// chacha20-poly1305 explicitly for a fleet of non-AES-NI hosts.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	CipherAES256  = "aes-256-gcm"
	CipherAES128  = "aes-128-gcm"
	CipherChaCha  = "chacha20-poly1305"
	CipherXChaCha = "xchacha20-poly1305"
	CipherDefault = CipherAES256
)

// Supported is the ordered list of concrete cipher names the engine accepts.
var Supported = []string{CipherAES256, CipherAES128, CipherChaCha, CipherXChaCha}

// Sealer seals and opens packet payloads with the configured AEAD.
type Sealer struct {
	aead cipher.AEAD
	Name string // resolved cipher name (never "auto")
}

// ResolveCipher maps a requested name (incl. aliases and "auto") to a concrete
// cipher. Unknown names are returned unchanged so NewSealer can reject them.
func ResolveCipher(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto":
		return CipherDefault // deterministic so both ends match regardless of CPU
	case CipherAES256, "aes", "aesgcm", "aes256", "aes-256":
		return CipherAES256
	case CipherAES128, "aes128", "aes-128":
		return CipherAES128
	case CipherChaCha, "chacha", "chacha20", "chachapoly":
		return CipherChaCha
	case CipherXChaCha, "xchacha", "xchacha20":
		return CipherXChaCha
	default:
		return name
	}
}

func deriveKey(psk, domain string, n int) []byte {
	k := sha256.Sum256([]byte("tnl-bip-aead|v1|" + domain + "|" + psk))
	return k[:n] // n bytes (16 for AES-128, 32 for the rest)
}

// NewSealer builds a Sealer for the named cipher (auto | aes-256-gcm |
// aes-128-gcm | chacha20-poly1305 | xchacha20-poly1305) keyed from psk.
func NewSealer(cipherName, psk string) (*Sealer, error) {
	name := ResolveCipher(cipherName)
	var (
		aead cipher.AEAD
		err  error
	)
	switch name {
	case CipherAES256:
		block, e := aes.NewCipher(deriveKey(psk, CipherAES256, 32))
		if e != nil {
			return nil, e
		}
		aead, err = cipher.NewGCM(block)
	case CipherAES128:
		block, e := aes.NewCipher(deriveKey(psk, CipherAES128, 16))
		if e != nil {
			return nil, e
		}
		aead, err = cipher.NewGCM(block)
	case CipherChaCha:
		aead, err = chacha20poly1305.New(deriveKey(psk, CipherChaCha, 32))
	case CipherXChaCha:
		aead, err = chacha20poly1305.NewX(deriveKey(psk, CipherXChaCha, 32))
	default:
		return nil, fmt.Errorf("unknown cipher %q (want one of aes-256-gcm, aes-128-gcm, chacha20-poly1305, xchacha20-poly1305)", cipherName)
	}
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead, Name: name}, nil
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
