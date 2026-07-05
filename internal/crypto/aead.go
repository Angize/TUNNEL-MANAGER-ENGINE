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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

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
//
// Nonces are NOT random per message. A random nonce would, by the birthday
// bound, collide after ~2^32 messages on a busy tunnel — catastrophic for GCM.
// Instead each Sealer picks a random per-process "session" prefix once at
// construction and appends a strictly-increasing 64-bit counter: the pair
// (prefix, counter) is unique for the life of the process, and a fresh random
// prefix on every restart avoids reuse across restarts (the counter alone would
// reset to 0 and reuse nonces). The counter also doubles as the anti-replay
// sequence number, and the prefix identifies the sender's boot session; Open
// returns both so the packet layer can drop replays.
type Sealer struct {
	aead   cipher.AEAD
	Name   string // resolved cipher name (never "auto")
	prefix []byte // random per-process nonce prefix (NonceSize-8 bytes)
	ctr    atomic.Uint64
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
	prefix := make([]byte, aead.NonceSize()-8) // 8 bytes reserved for the counter
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return nil, err
	}
	return &Sealer{aead: aead, Name: name, prefix: prefix}, nil
}

// Overhead is the number of bytes Seal adds to a plaintext (nonce + tag).
func (s *Sealer) Overhead() int {
	return s.aead.NonceSize() + s.aead.Overhead()
}

// sessionID compresses a nonce prefix into a 64-bit id used only to key the
// receiver's anti-replay window. A collision merely resets a window early, which
// is safe, so a right-aligned truncation to 8 bytes is enough.
func sessionID(prefix []byte) uint64 {
	var b [8]byte
	n := len(prefix)
	if n > 8 {
		n = 8
	}
	copy(b[8-n:], prefix[:n])
	return binary.BigEndian.Uint64(b[:])
}

// Seal returns nonce||ciphertext where nonce = sessionPrefix||counter. The
// counter increments on every call, so a nonce is never reused within this
// process, and the random prefix keeps it distinct across restarts.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	nonce := make([]byte, ns)
	copy(nonce, s.prefix)
	binary.BigEndian.PutUint64(nonce[ns-8:], s.ctr.Add(1))
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal, returning the sender's session id and per-message sequence
// number (both drawn from the authenticated nonce) alongside the plaintext. It
// returns an error on any authentication failure.
func (s *Sealer) Open(sealed []byte) (session uint64, seq uint64, pt []byte, err error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return 0, 0, nil, errors.New("sealed payload too short")
	}
	nonce := sealed[:ns]
	pt, err = s.aead.Open(nil, nonce, sealed[ns:], nil)
	if err != nil {
		return 0, 0, nil, err
	}
	return sessionID(nonce[:ns-8]), binary.BigEndian.Uint64(nonce[ns-8:]), pt, nil
}
