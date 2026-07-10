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
// Note: 253 (protoBIP) is deliberately EXCLUDED — flux's raw carrier installs a per-peer PREROUTING
// DROP for every pool proto, which would silently black-hole a co-located raw/"bip" tunnel to the
// same peer (bip rides proto 253). 246 takes its slot; both ends derive from this list so they stay
// in sync (a breaking change is fine — no on-wire backward-compat is kept).
var fluxProtoPool = []int{254, 252, 251, 250, 249, 248, 247, 246}

// fluxDportPool is the set of UDP destination ports the "udp" flux carrier rotates
// through. Every entry is a universally-passed QUIC/STUN/WebRTC media port, so the
// flow looks like ordinary real-time UDP to any transit while the 4-tuple still
// moves each epoch (a moving target with no odd port to flag). The source port is
// drawn from the ephemeral range, which is exactly what a real client would use.
var fluxDportPool = []uint16{443, 3478, 19302, 5349, 8801}

// fluxStunDports is the destination-port pool for the "stun" carrier — STUN/TURN
// ports only, since that carrier additionally wraps each frame in a real STUN
// Binding header so the flow parses as WebRTC signalling, not just generic UDP.
var fluxStunDports = []uint16{3478, 19302, 5349}

// defaultFluxRotate is the epoch length when the config leaves flux_rotate_secs
// unset. Ten minutes trades rotation agility against how often the (cheap)
// statistical shape churns; "rotate now" from the panel bumps the epoch out of band.
const defaultFluxRotate = 600 * time.Second

// fluxShape is the per-epoch carrier descriptor. It is a pure function of
// (PSK, epoch, shapeProfile): both ends derive the same one from the clock alone.
// Which fields are used on the wire depends on the configured carrier — "raw" rides
// proto, "udp"/"stun" ride sport + a carrier-specific destination port.
type fluxShape struct {
	epoch     int64
	proto     int    // raw carrier: rotating IP protocol number this epoch
	sport     uint16 // udp/stun carrier: rotating source port (ephemeral range)
	dport     uint16 // udp carrier: rotating destination port (from fluxDportPool)
	dportSTUN uint16 // stun carrier: rotating destination port (STUN/TURN ports only)
	ctrlPad   int    // control-frame (ping/pong) padding budget — the shape profile's size signature
}

// dportFor returns the destination port to use for the given carrier this epoch.
func (s fluxShape) dportFor(carrier string) uint16 {
	if carrier == "stun" {
		return s.dportSTUN
	}
	return s.dport
}

// shapeCtrlPad maps a statistical shape profile to the padding budget for tiny
// control frames (keepalives), which are otherwise the most fingerprintable
// fixed-size packets. Data frames stay near the MTU and are already varied, so the
// profile shapes the SMALL-packet size histogram to resemble the mimicked traffic:
// webrtc → small RTP-ish, quic → short-ack-ish, video → larger bursts. This is
// coarse size-shaping (no added latency, no MTU cost), not full statistical mimicry.
func shapeCtrlPad(shape string, x byte) int {
	switch shape {
	case "quic":
		return 24 + int(x)%56 // 24..79
	case "video":
		return 64 + int(x)%160 // 64..223 — larger, bursty
	case "webrtc":
		return 8 + int(x)%48 // 8..55 — small RTP-ish
	default: // "random"
		return 16 + int(x)%240 // 16..255 (matches the control padding budget)
	}
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

// deriveFluxShape expands (PSK, epoch, shapeProfile) into the epoch's carrier shape
// via HKDF, domain-separated from the session-key KDF so the two never derive the
// same bytes. shape is the statistical profile ("quic"/"video"/"webrtc"/"random").
func deriveFluxShape(psk string, epoch int64, shape string) fluxShape {
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(epoch))
	kdf := hkdf.New(sha256.New, []byte(psk), eb[:], []byte("tnl-flux|v1|shape"))
	var b [16]byte
	_, _ = io.ReadFull(kdf, b[:])
	return fluxShape{
		epoch:     epoch,
		proto:     fluxProtoPool[int(b[0])%len(fluxProtoPool)],
		dport:     fluxDportPool[int(b[1])%len(fluxDportPool)],
		dportSTUN: fluxStunDports[int(b[1])%len(fluxStunDports)],
		sport:     uint16(20000 + int(binary.BigEndian.Uint16(b[2:4]))%40000), // 20000..59999
		ctrlPad:   shapeCtrlPad(shape, b[5]),
	}
}

// graceShapes returns the shapes acceptable around the given center epoch: those
// derived for the previous, current, and next epoch. Accepting the neighbours
// absorbs modest clock skew between the ends and any packet in flight when the
// epoch ticked, so traffic never drops at a rotation boundary even though neither
// side sends a rotation signal. The AEAD still authenticates every frame, so
// widening the carrier filter never weakens security. The center epoch already
// includes any manual epoch offset (see Flux.epochNow).
func graceShapes(psk string, epoch int64, shape string) []fluxShape {
	return []fluxShape{
		deriveFluxShape(psk, epoch-1, shape),
		deriveFluxShape(psk, epoch, shape),
		deriveFluxShape(psk, epoch+1, shape),
	}
}

// graceProtos is the raw-carrier view of graceShapes: the acceptable IP protocols.
func graceProtos(psk string, epoch int64, shape string) map[int]bool {
	set := make(map[int]bool, 3)
	for _, sh := range graceShapes(psk, epoch, shape) {
		set[sh.proto] = true
	}
	return set
}

// graceDports is the udp/stun-carrier view of graceShapes: the acceptable UDP
// destination ports for the given carrier.
func graceDports(psk string, epoch int64, shape, carrier string) map[uint16]bool {
	set := make(map[uint16]bool, 3)
	for _, sh := range graceShapes(psk, epoch, shape) {
		set[sh.dportFor(carrier)] = true
	}
	return set
}
