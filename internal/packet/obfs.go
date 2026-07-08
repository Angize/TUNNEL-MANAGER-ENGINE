// This file implements the optional "obfs" (anti-DPI) framing shared by both
// core carriers. When obfuscation is on the wire carries NO constant bytes:
//
//   - The frame type (data/ping/pong) is folded into the AEAD-sealed plaintext
//     instead of riding in a cleartext header, so the old constant magic byte
//     (0xB1) — a trivial DPI signature — is gone entirely.
//   - Random padding of variable length is appended before sealing, so packet
//     sizes no longer form a fixed pattern (keepalives especially).
//   - Over TCP the 2-byte length prefix is masked with a ChaCha20 keystream
//     derived from the PSK and a per-connection random salt, so even the framing
//     length looks random.
//
// The result on the wire is a stream/datagram of bytes indistinguishable from
// random. A peer that cannot AEAD-open a frame (a DPI active-probe, a wrong
// PSK) is dropped without any identifying response — this is what gives the
// carrier its probe resistance.
package packet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20"
)

const (
	obfsSaltLen = 24 // XChaCha20 nonce size; sent in the clear (uniformly random)

	// Padding budgets. Control frames (ping/pong) are tiny and the most
	// fingerprintable, so they get padded up to a larger random size to look
	// like data; data frames get a small random jitter to avoid pushing a
	// full-MTU packet far past the path MTU. obfsDataPadMax is also reserved in
	// the node's MTU math so a padded data frame never fragments.
	obfsDataPadMax = 64
	obfsCtrlPadMax = 256

	// obfsInnerHdr is the fixed inner header folded into the sealed plaintext:
	// [type:1][realLen:2].
	obfsInnerHdr = 3
)

// deriveObfsKey produces the 32-byte ChaCha20 key used to mask TCP length
// prefixes. It is domain-separated from the AEAD key so the two never collide.
func deriveObfsKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core-obfs|v1|len|" + psk))
	return k[:32]
}

// newObfsStream builds a ChaCha20 keystream generator from the PSK-derived key
// and a per-connection salt. Callers XOR successive length prefixes with the
// bytes it yields; both ends advance identically because TCP is ordered.
func newObfsStream(psk string, salt []byte) (*chacha20.Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(deriveObfsKey(psk), salt)
}

// randPad returns n random bytes of padding, n UNIFORM in [0, max]. It uses
// rejection sampling rather than `% (max+1)`: modulo of a single byte biases the
// low lengths (e.g. for max=64, 256 mod 65 leaves 0..60 slightly more likely and
// values > 255 unreachable), which narrows the size histogram a DPI classifier
// sees. Rejection keeps the distribution flat.
func randUint(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	n := uint32(max) + 1
	limit := (0xFFFFFFFF/n)*n - 1 // largest multiple of n that fits in uint32, minus 1
	var b [4]byte
	for {
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint32(b[:])
		if v <= limit {
			return int(v % n), nil
		}
	}
}

func randPad(max int) ([]byte, error) {
	n, err := randUint(max)
	if err != nil || n == 0 {
		return nil, err
	}
	pad := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, pad); err != nil {
		return nil, err
	}
	return pad, nil
}

// obfsSeal packs [type][realLen][payload][random-pad] and AEAD-seals it. The
// returned bytes carry no constant fields (the sealer prepends a random nonce).
func obfsSeal(s Sealer, typ byte, payload []byte, padMax int) ([]byte, error) {
	pad, err := randPad(padMax)
	if err != nil {
		return nil, err
	}
	inner := make([]byte, obfsInnerHdr+len(payload)+len(pad))
	inner[0] = typ
	binary.BigEndian.PutUint16(inner[1:3], uint16(len(payload)))
	copy(inner[obfsInnerHdr:], payload)
	copy(inner[obfsInnerHdr+len(payload):], pad)
	return s.Seal(inner, nil) // type is folded into the sealed plaintext, no aad needed
}

// obfsOpen reverses obfsSeal, returning the frame type, the sender's
// (session, seq) for anti-replay, and the real payload (padding stripped). Any
// authentication failure or malformed frame errors.
func obfsOpen(s Sealer, sealed []byte) (typ byte, session uint64, seq uint64, payload []byte, err error) {
	session, seq, inner, err := s.Open(sealed, nil)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if len(inner) < obfsInnerHdr {
		return 0, 0, 0, nil, errors.New("obfs: short inner frame")
	}
	realLen := int(binary.BigEndian.Uint16(inner[1:3]))
	if obfsInnerHdr+realLen > len(inner) {
		return 0, 0, 0, nil, errors.New("obfs: inner length overflow")
	}
	return inner[0], session, seq, inner[obfsInnerHdr : obfsInnerHdr+realLen], nil
}

// padMaxFor picks the padding budget for a frame type.
func padMaxFor(typ byte) int {
	if typ == typeData {
		return obfsDataPadMax
	}
	return obfsCtrlPadMax
}

// jitter returns base perturbed by up to ±33% so keepalives do not emit on a
// fixed period a DPI box could time. It never returns less than base/2.
func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	span := int64(base) * 2 / 3 // total jitter window = 2/3 of base
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return base
	}
	delta := int64(binary.BigEndian.Uint64(b[:])%uint64(span+1)) - span/2
	d := int64(base) + delta
	if d < int64(base)/2 {
		d = int64(base) / 2
	}
	return time.Duration(d)
}
