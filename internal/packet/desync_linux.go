//go:build linux

// Fake-packet desync: a content-agnostic anti-DPI mechanism shared by the raw and flux
// carriers (the two that build the whole IPv4 header via IP_HDRINCL, so they can forge a
// TTL/checksum). Just before each handshake the client emits a few DECOY packets to the
// peer:
//
//   - a low-TTL decoy expires a few hops out — it reaches an on-path DPI but dies before
//     the server, so the server never sees it (sent via IP_HDRINCL, which honours the TTL);
//   - a bad-checksum decoy is discarded by the first hop that validates the IP checksum (most
//     routers, and the server's own stack) — it must be injected at L2 via AF_PACKET, because
//     an IP_HDRINCL socket ALWAYS recomputes the checksum and would silently repair it.
//
// Either way a STATEFUL DPI that tracks the flow ingests the decoys and mis-syncs its
// per-flow state, while the real, AEAD-authenticated session is untouched (a decoy that does
// reach the server carries random bytes and cannot open). This is the paqet/zapret "fake
// before handshake" idea, done natively for the carriers we fully control. It has no effect
// on the kernel-socket carriers (udp/tcp/ws), which cannot forge the header.
package packet

import "crypto/rand"

// injectMaxTTL caps the TTL of a kernel-TCP inject decoy (tcp/cover/ws). Unlike a raw/flux decoy
// (sent to a peer we don't hold a live kernel connection to), an inject decoy rides a REAL
// connection's 4-tuple — a well-formed segment that reached the server would draw an RST or a
// challenge-ACK that could disturb the real flow. Clamping the TTL here guarantees the decoy
// expires on the path (where the DPI still ingests it) no matter how high the operator set fake_ttl.
const injectMaxTTL = 8

// desyncCfg holds the client-side fake-packet-desync parameters. The zero value is off.
type desyncCfg struct {
	on    bool
	ttl   int    // hop budget stamped on a low-TTL decoy (it expires before the server)
	count int    // decoys emitted per handshake cycle
	mode  string // "ttl" | "badsum" | "both"
}

// newDesyncCfg normalises the config values (applying the same defaults the node/panel
// use) and returns an off config when on is false.
func newDesyncCfg(on bool, ttl, count int, mode string) desyncCfg {
	if !on {
		return desyncCfg{}
	}
	if ttl <= 0 {
		ttl = 4
	}
	if count <= 0 {
		count = 2
	}
	switch mode {
	case "ttl", "badsum", "both":
	default:
		mode = "ttl"
	}
	return desyncCfg{on: true, ttl: ttl, count: count, mode: mode}
}

// usesBadsum reports whether any decoy this config emits carries a corrupted checksum, so a
// carrier knows to set up the AF_PACKET injector (IP_HDRINCL would repair the checksum).
func (d desyncCfg) usesBadsum() bool { return d.on && (d.mode == "badsum" || d.mode == "both") }

// fakeSpec is one decoy's IP-header knobs. A ttl decoy keeps a valid checksum (it must be
// forwarded until the TTL runs out mid-path); a badsum decoy keeps a normal TTL (it must
// reach the server host to be dropped there). The two are complementary, so "both"
// alternates them.
type fakeSpec struct {
	ttl    int
	badSum bool
}

// specs returns the per-decoy header knobs for this config (len == count, empty when off).
func (d desyncCfg) specs() []fakeSpec {
	if !d.on {
		return nil
	}
	out := make([]fakeSpec, 0, d.count)
	for i := 0; i < d.count; i++ {
		bad := d.mode == "badsum" || (d.mode == "both" && i%2 == 1)
		ttl := d.ttl
		if bad {
			ttl = 64 // a bad-checksum decoy should reach the server host, so give it a live TTL
		}
		out = append(out, fakeSpec{ttl: ttl, badSum: bad})
	}
	return out
}

// specsTCP is specs() for the kernel-TCP inject path (tcp/cover/ws): every decoy keeps the LOW
// TTL and is never promoted to 64, because a well-formed-looking segment on a REAL connection's
// 4-tuple must not reach the server (it would draw an RST / challenge-ACK); the low TTL makes it
// die on the path, where the DPI still sees it. badsum still corrupts the checksum for extra
// insurance against a DPI that validates it.
func (d desyncCfg) specsTCP() []fakeSpec {
	if !d.on {
		return nil
	}
	ttl := d.ttl
	if ttl > injectMaxTTL {
		ttl = injectMaxTTL // never let an inject decoy reach the server, however high fake_ttl was set
	}
	out := make([]fakeSpec, 0, d.count)
	for i := 0; i < d.count; i++ {
		bad := d.mode == "badsum" || (d.mode == "both" && i%2 == 1)
		out = append(out, fakeSpec{ttl: ttl, badSum: bad}) // always the (clamped) configured low TTL
	}
	return out
}

// fakePayload returns a random-length, random-content payload sized like a small
// handshake/keepalive frame. Our real frames are AEAD ciphertext (indistinguishable from
// random on the wire), so a random decoy of a plausible size resembles a real flow packet.
func fakePayload() []byte {
	var lb [1]byte
	_, _ = rand.Read(lb[:])
	n := 48 + int(lb[0])%64 // 48..111 bytes
	p := make([]byte, n)
	_, _ = rand.Read(p)
	return p
}
