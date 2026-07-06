// Package-level flux shape derivation, kept platform-independent (and therefore
// unit-testable) apart from the socket work in flux_linux.go.
//
// flux is a polymorphic, moving-target carrier. Unlike the fixed raw profiles
// (bip/ipip/gre/... each pinned to one IP protocol number), flux derives its
// carrier *shape* from the pre-shared key and a time-based epoch, and both ends
// recompute it independently from the wall clock — so the shape rotates in
// lock-step with NO negotiation packet on the wire to fingerprint or to signal a
// rotation. The decode is shape-INDEPENDENT (the sealed frame is identical
// regardless of the carrier), which is what makes a rotation free: it changes
// only how packets look, never how they are opened, so no re-handshake is needed.
//
// This file derives, for a given epoch:
//   - proto:  the IP protocol number the raw carrier rides this epoch
//   - padMax: the per-frame random padding budget (coarse size shaping)
//
// The receiver cannot bind a single-protocol socket (the protocol moves), so
// flux_linux.go sends via IP_HDRINCL (any protocol from one socket) and receives
// via AF_PACKET (every protocol), filtering to the small set of protocols that
// the current, previous, and next epochs derive (the grace window that absorbs
// clock skew and in-flight packets across a rotation boundary).
package packet

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// fluxProtoPool is the set of IP protocol numbers the "raw" flux carrier rotates
// through. Every entry sits in the unassigned/experimental range, so the kernel
// attaches no L4 semantics to them (it emits no RST/port-unreachable and does not
// try to parse a transport header) — the inner AEAD tag is the only real check.
// Keep this list stable: it is part of the wire contract both ends derive against.
//
// The raw carrier only survives where these exotic protocols reach the peer
// (same-segment / L2-adjacent / a cooperative datacenter). Across the open
// internet most transit drops anything that is not TCP/UDP/ICMP, so the "udp"
// carrier below is the internet-safe default.
var fluxProtoPool = []int{253, 254, 252, 251, 250, 249, 248, 247}

// fluxDportPool is the set of UDP destination ports the "udp" flux carrier rotates
// through. Every entry is a universally-passed QUIC/STUN/WebRTC media port, so the
// flow looks like ordinary real-time UDP to any transit while the 4-tuple still
// moves each epoch (a moving target with no odd port to flag). The source port is
// drawn from the ephemeral range, which is exactly what a real client would use.
var fluxDportPool = []uint16{443, 3478, 19302, 5349, 8801}

// defaultFluxRotate is the epoch length when the config leaves flux_rotate_secs
// unset. Ten minutes trades rotation agility against how often the (cheap)
// statistical shape churns; "rotate now" from the panel bumps the epoch out of band.
const defaultFluxRotate = 600 * time.Second

// fluxShape is the per-epoch carrier descriptor. It is a pure function of
// (PSK, epoch): both ends derive the same one from the clock alone. Which fields
// are used on the wire depends on the configured carrier — "raw" rides proto,
// "udp" rides sport/dport.
type fluxShape struct {
	epoch  int64
	proto  int    // raw carrier: rotating IP protocol number this epoch
	sport  uint16 // udp carrier: rotating source port (ephemeral range)
	dport  uint16 // udp carrier: rotating destination port (from fluxDportPool)
	padMax int    // per-frame random padding budget (size shaping)
}

// fluxEpochAt returns the epoch index for time t under the given rotation period.
// epoch = floor(unixNanos / rotateNanos); a non-positive rotate falls back to the
// default so a misconfigured link still rotates rather than dividing by zero.
func fluxEpochAt(rotate time.Duration, t time.Time) int64 {
	if rotate <= 0 {
		rotate = defaultFluxRotate
	}
	return t.UnixNano() / int64(rotate)
}

// deriveFluxShape expands (PSK, epoch) into the epoch's carrier shape via HKDF,
// domain-separated from the session-key KDF so the two never derive the same bytes.
func deriveFluxShape(psk string, epoch int64) fluxShape {
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(epoch))
	kdf := hkdf.New(sha256.New, []byte(psk), eb[:], []byte("tnl-flux|v1|shape"))
	var b [16]byte
	_, _ = io.ReadFull(kdf, b[:])
	return fluxShape{
		epoch:  epoch,
		proto:  fluxProtoPool[int(b[0])%len(fluxProtoPool)],
		dport:  fluxDportPool[int(b[1])%len(fluxDportPool)],
		sport:  uint16(20000 + int(binary.BigEndian.Uint16(b[2:4]))%40000), // 20000..59999
		padMax: 16 + int(b[5])%80,                                          // 16..95 bytes of jitter
	}
}

// graceShapes returns the shapes acceptable *right now*: those derived for the
// previous, current, and next epoch. Accepting the neighbours absorbs modest clock
// skew between the ends and any packet in flight when the epoch ticked, so traffic
// never drops at a rotation boundary even though neither side sends a rotation
// signal. The AEAD still authenticates every frame, so widening the carrier filter
// never weakens security. The receiver turns these into a protocol set (raw
// carrier) or a destination-port set (udp carrier).
func graceShapes(psk string, rotate time.Duration, t time.Time) []fluxShape {
	e := fluxEpochAt(rotate, t)
	return []fluxShape{
		deriveFluxShape(psk, e-1),
		deriveFluxShape(psk, e),
		deriveFluxShape(psk, e+1),
	}
}

// graceProtos is the raw-carrier view of graceShapes: the acceptable IP protocols.
func graceProtos(psk string, rotate time.Duration, t time.Time) map[int]bool {
	set := make(map[int]bool, 3)
	for _, sh := range graceShapes(psk, rotate, t) {
		set[sh.proto] = true
	}
	return set
}

// graceDports is the udp-carrier view of graceShapes: the acceptable UDP dest ports.
func graceDports(psk string, rotate time.Duration, t time.Time) map[uint16]bool {
	set := make(map[uint16]bool, 3)
	for _, sh := range graceShapes(psk, rotate, t) {
		set[sh.dport] = true
	}
	return set
}
