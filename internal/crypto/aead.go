// Package crypto provides the AEAD sealing used by the core carrier.
//
// Two AEADs are supported and selected by name: AES-256-GCM (stdlib, fastest on
// AES-NI hosts) and ChaCha20-Poly1305 (constant-time in software, faster on
// hosts without AES acceleration such as many ARM boards). Both ends of a tunnel
// MUST use the same cipher and PSK.
//
// Directional keys (v2). The AEAD key is derived PER DIRECTION — the client→server
// key differs from server→client — so each sealing key is used by exactly ONE
// sealer in a tunnel. That removes the (key, nonce) reuse risk that a single
// bidirectional key had (two independent sealers could pick the same random nonce
// prefix), and means a frame captured in one direction is not a valid frame in the
// other. A node's Sealer is built with isClient so it seals with its send-direction
// key and opens with the peer's.
//
// Wire masking (v2). The AEAD nonce would otherwise ride on the wire in the clear
// with its high counter bytes fixed at zero — a stateless DPI signature that a
// censor can match on even through the obfs layer. To kill it, every sealed frame
// is XOR-masked with a per-direction ChaCha20 keystream seeded by a fresh random
// per-frame salt; the salt is prepended. The result is uniformly random on the
// wire: no fixed offset, no zero bytes. The mask is obfuscation only — the AEAD
// tag under it still provides all authentication.
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

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	CipherAES256  = "aes-256-gcm"
	CipherAES128  = "aes-128-gcm"
	CipherChaCha  = "chacha20-poly1305"
	CipherXChaCha = "xchacha20-poly1305"
	CipherDefault = CipherAES256

	maskSaltLen = 12 // random per-frame salt seeding the wire mask (ChaCha20 nonce)
	maskKeyLen  = 32 // ChaCha20 key length for the wire mask
)

// Supported is the ordered list of concrete cipher names the core accepts.
var Supported = []string{CipherAES256, CipherAES128, CipherChaCha, CipherXChaCha}

// Sealer seals and opens packet payloads with the configured AEAD, using
// direction-separated keys and a wire mask (see the package comment).
//
// Nonces are NOT random per message. A random nonce would, by the birthday
// bound, collide after ~2^32 messages on a busy tunnel — catastrophic for GCM.
// Instead each Sealer picks a random per-process "session" prefix once at
// construction and appends a strictly-increasing 64-bit counter: the pair
// (prefix, counter) is unique for the life of the process, and a fresh random
// prefix on every restart avoids reuse across restarts. Because the send key is
// used by only ONE sealer, that pair is never shared with another sealer either.
// The counter doubles as the anti-replay sequence number and the prefix
// identifies the sender's boot session; Open returns both.
type Sealer struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendMask []byte // ChaCha20 key masking our outbound frames
	recvMask []byte // ChaCha20 key unmasking the peer's inbound frames
	Name     string // resolved cipher name (never "auto")
	prefix   []byte // random per-process nonce prefix (NonceSize-8 bytes)
	ctr      atomic.Uint64
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

// deriveKey derives an n-byte key bound to a label (which encodes the purpose and
// direction) and the PSK. v2 domain: keys are NOT compatible with the old
// single-key scheme, which is intentional — both ends upgrade together.
func deriveKey(psk, label string, n int) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|" + label + "|" + psk))
	return k[:n] // n bytes (16 for AES-128, 32 for the rest)
}

// aeadFactory returns a constructor + key length for the named cipher.
func aeadFactory(name string) (mk func(key []byte) (cipher.AEAD, error), keyLen int, err error) {
	switch name {
	case CipherAES256:
		return func(k []byte) (cipher.AEAD, error) {
			b, e := aes.NewCipher(k)
			if e != nil {
				return nil, e
			}
			return cipher.NewGCM(b)
		}, 32, nil
	case CipherAES128:
		return func(k []byte) (cipher.AEAD, error) {
			b, e := aes.NewCipher(k)
			if e != nil {
				return nil, e
			}
			return cipher.NewGCM(b)
		}, 16, nil
	case CipherChaCha:
		return func(k []byte) (cipher.AEAD, error) { return chacha20poly1305.New(k) }, 32, nil
	case CipherXChaCha:
		return func(k []byte) (cipher.AEAD, error) { return chacha20poly1305.NewX(k) }, 32, nil
	default:
		return nil, 0, fmt.Errorf("unknown cipher %q (want one of aes-256-gcm, aes-128-gcm, chacha20-poly1305, xchacha20-poly1305)", name)
	}
}

// NewSealer builds a Sealer for the named cipher keyed statically from psk.
// isClient selects which direction key it seals with (client seals c→s, opens
// s→c; server the reverse), so the two ends of a tunnel interoperate. This is the
// pre-handshake / no-forward-secrecy path; sealerFromKeys is used once an
// ephemeral session is negotiated (see handshake.go).
//
// VALIDATION/BOOTSTRAP ONLY — do NOT seal live traffic with this. The keys are a
// pure function of the PSK, so the send counter restarts from 0 every run: two
// processes (or one after a restart) would reuse (key, nonce) pairs and void the
// AEAD's confidentiality/integrity. It exists solely to fail fast on a bad
// cipher/PSK at startup (main.go keeps only s.Name and drops the sealer). All real
// frames go through SessionSealer, whose keys are salted by a fresh per-session
// ephemeral so no two sessions — and no restart — ever share a keystream.
func NewSealer(cipherName, psk string, isClient bool) (*Sealer, error) {
	name := ResolveCipher(cipherName)
	_, keyLen, err := aeadFactory(name)
	if err != nil {
		return nil, err
	}
	return sealerFromKeys(name,
		deriveKey(psk, "aead|c2s|"+name, keyLen),
		deriveKey(psk, "aead|s2c|"+name, keyLen),
		deriveKey(psk, "mask|c2s", maskKeyLen),
		deriveKey(psk, "mask|s2c", maskKeyLen),
		isClient)
}

// sealerFromKeys assembles a Sealer from already-derived per-direction key
// material (AEAD keys + wire-mask keys). The caller supplies the c→s and s→c
// keys; isClient wires send/recv to the right one. Used by both the static PSK
// path (NewSealer) and the ephemeral handshake path.
func sealerFromKeys(name string, c2sKey, s2cKey, c2sMask, s2cMask []byte, isClient bool) (*Sealer, error) {
	mk, _, err := aeadFactory(name)
	if err != nil {
		return nil, err
	}
	s := &Sealer{Name: name}
	var sendKey, recvKey []byte
	if isClient {
		sendKey, recvKey = c2sKey, s2cKey
		s.sendMask, s.recvMask = c2sMask, s2cMask
	} else {
		sendKey, recvKey = s2cKey, c2sKey
		s.sendMask, s.recvMask = s2cMask, c2sMask
	}
	if s.sendAEAD, err = mk(sendKey); err != nil {
		return nil, err
	}
	if s.recvAEAD, err = mk(recvKey); err != nil {
		return nil, err
	}
	s.prefix = make([]byte, s.sendAEAD.NonceSize()-8) // 8 bytes reserved for the counter
	if _, err := io.ReadFull(rand.Reader, s.prefix); err != nil {
		return nil, err
	}
	return s, nil
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

// mask XORs buf in place with the ChaCha20 keystream keyed by (key, salt).
func mask(key, salt, buf []byte) error {
	c, err := chacha20.NewUnauthenticatedCipher(key, salt)
	if err != nil {
		return err
	}
	c.XORKeyStream(buf, buf)
	return nil
}

// Seal returns salt || mask(nonce||ciphertext||tag). aad is authenticated but not
// transmitted (callers pass the cleartext frame header so it cannot be flipped).
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	ns := s.sendAEAD.NonceSize()
	nonce := make([]byte, ns)
	copy(nonce, s.prefix)
	binary.BigEndian.PutUint64(nonce[ns-8:], s.ctr.Add(1))
	sealed := s.sendAEAD.Seal(nonce, nonce, plaintext, aad) // nonce||ct||tag

	out := make([]byte, maskSaltLen+len(sealed))
	if _, err := io.ReadFull(rand.Reader, out[:maskSaltLen]); err != nil {
		return nil, err
	}
	copy(out[maskSaltLen:], sealed)
	if err := mask(s.sendMask, out[:maskSaltLen], out[maskSaltLen:]); err != nil {
		return nil, err
	}
	return out, nil
}

// Open reverses Seal, returning the sender's session id and per-message sequence
// number (both from the authenticated nonce) alongside the plaintext. aad must
// match the value passed to Seal. Any authentication failure returns an error.
func (s *Sealer) Open(wire, aad []byte) (session uint64, seq uint64, pt []byte, err error) {
	ns := s.recvAEAD.NonceSize()
	if len(wire) < maskSaltLen+ns {
		return 0, 0, nil, errors.New("sealed payload too short")
	}
	body := make([]byte, len(wire)-maskSaltLen)
	copy(body, wire[maskSaltLen:])
	if err := mask(s.recvMask, wire[:maskSaltLen], body); err != nil {
		return 0, 0, nil, err
	}
	nonce := body[:ns]
	pt, err = s.recvAEAD.Open(nil, nonce, body[ns:], aad)
	if err != nil {
		return 0, 0, nil, err
	}
	return sessionID(nonce[:ns-8]), binary.BigEndian.Uint64(nonce[ns-8:]), pt, nil
}
