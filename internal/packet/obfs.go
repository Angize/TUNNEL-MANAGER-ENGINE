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

// randUint returns a random int UNIFORM in [0, max]. It uses
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

// obfsSeal packs [type][realLen][payload][pad] and AEAD-seals it. The returned bytes carry no constant
// fields (the sealer prepends a random nonce). Only the pad LENGTH matters (it's the size-shaping defense
// and is random via randUint); its bytes do NOT — the pad rides INSIDE the AEAD envelope and obfsOpen
// strips it by realLen without reading it. So the pad region is just left as make()'s zero fill: under a
// non-repeating nonce the sealed ciphertext over a zero pad is keystream, i.e. still indistinguishable
// from random on the wire, so this skips a per-packet crypto/rand fill of up to padMax bytes with no
// change to the wire-looks-random property and no security effect (AEAD IND-CPA covers any plaintext).
func obfsSeal(s Sealer, typ byte, payload []byte, padMax int) ([]byte, error) {
	n, err := randUint(padMax)
	if err != nil {
		return nil, err
	}
	inner := make([]byte, obfsInnerHdr+len(payload)+n)
	inner[0] = typ
	binary.BigEndian.PutUint16(inner[1:3], uint16(len(payload)))
	copy(inner[obfsInnerHdr:], payload)
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

// frac53 maps 8 bytes to a uniform float64 in [0,1) using the top 53 bits (the mantissa width, so
// every value is exactly representable). b must be at least 8 bytes.
func frac53(b []byte) float64 {
	return float64(binary.BigEndian.Uint64(b)>>11) / float64(uint64(1)<<53)
}

// keepaliveInterval returns the next client keepalive delay. A fixed clock — or even a bare
// symmetric ±33% jitter — is a passive TIMING fingerprint: an adversary that averages the
// inter-arrival of a long-lived flow's small control packets recovers the mean exactly, and a whole
// fleet pinned to the same keepalive beacons in lockstep (a cross-flow correlation signal). Two
// defenses over jitter():
//
//   - a per-TUNNEL mean shift derived from the PSK. Keepalive is client-local (the peer only
//     reflects pongs), so the two ends need not agree on the period; deriving it from the PSK gives
//     each tunnel a different, stable mean, so there is no single fleet-wide constant to recover and
//     different tunnels do not step together.
//   - a wider, TRIANGULAR per-fire spread (mean of two uniforms) so one flow's own mean is harder to
//     average out than a tight uniform band.
//
// The result is clamped to [0.6,1.3]×base so a live-but-idle client still pings well within the
// server's idleMult×keepalive read deadline (idleMult>=4 ⇒ 1.3×base ≪ 4×base) and the
// pingLossThreshold dead-detection window stays bounded (<= pingLossThreshold×1.3×base).
func keepaliveInterval(base time.Duration, psk string) time.Duration {
	if base <= 0 {
		return base
	}
	// per-tunnel mean in [0.85,1.20]×base, deterministic from the PSK.
	h := sha256.Sum256([]byte("tnl-core|ka-phase|" + psk))
	mean := float64(base) * (0.85 + 0.35*frac53(h[:8]))
	var rb [16]byte
	if _, err := io.ReadFull(rand.Reader, rb[:]); err != nil {
		return time.Duration(mean)
	}
	// triangular spread in ~[0.66,1.34], heavier at the center than a single uniform.
	spread := 1.0 + 0.68*((frac53(rb[0:8])+frac53(rb[8:16]))/2.0-0.5)
	d := mean * spread
	if lo := float64(base) * 0.6; d < lo {
		d = lo
	}
	if hi := float64(base) * 1.3; d > hi {
		d = hi
	}
	return time.Duration(d)
}
