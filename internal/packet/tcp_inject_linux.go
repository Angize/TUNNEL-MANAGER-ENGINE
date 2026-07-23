//go:build linux

// TCP-segment injection desync for the kernel-socket TCP-family carriers (tcp / cover / ws).
// The real connection stays kernel-owned; right after it connects we inject a few DECOY TCP
// segments on its exact 4-tuple, wrapped in a low-TTL IPv4 header and pushed at L2 via
// AF_PACKET. A stateful DPI on the path ingests them and mis-syncs its per-flow state, while
// the decoys expire before the edge/server (low TTL) so they never enter the real stream —
// the kernel's TCP is untouched. This is the "inject fake segments alongside a real flow"
// (zapret/nfqws) model; it works on our AEAD ciphertext because it is content-agnostic (it
// disrupts flow-tracking, not content). See inject_linux.go for the AF_PACKET primitive.
package packet

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
)

// sendTCPFakes injects the configured decoy segments on conn's 4-tuple just after connect. It
// is best-effort: xhttp's synthetic conn addresses fail the *net.TCPAddr assertion and are
// skipped; a missing CAP_NET_RAW (AF_PACKET) or an unresolvable next hop just drops the decoys.
// The injector is one-shot per connect — the next-hop neighbour is guaranteed warm here (the
// kernel just completed the 3-way handshake through it), so resolveL2 succeeds immediately.
func (b *TCP) sendTCPFakes(conn net.Conn) {
	if !b.dsOn || conn == nil {
		return
	}
	la, ok1 := conn.LocalAddr().(*net.TCPAddr)
	ra, ok2 := conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return // synthetic addrs (xhttp) — no real 4-tuple to mirror
	}
	src, dst := la.IP.To4(), ra.IP.To4()
	if src == nil || dst == nil {
		return // an IPv6 4-tuple — the raw IPv4 injector can't mirror it
	}
	inj, err := newL2Inject(ra.IP)
	if err != nil {
		b.dsFailOnce.Do(func() {
			log.Printf("tcp: desync decoys disabled (AF_PACKET: %v) — the carrier needs CAP_NET_RAW", err)
		})
		return
	}
	defer inj.close()
	d := newDesyncCfg(b.dsOn, b.dsTTL, b.dsCount, b.dsMode)
	for _, sp := range d.specsTCP() {
		seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), randSeq32(), randSeq32(), tcpPshAck, 0xffff, fakePayload())
		if ip := buildIP4Ext(src, dst, protoTCP, sp.ttl, sp.badSum, seg); ip != nil {
			_ = inj.send(ip)
		}
	}
}

// randSeq32 returns a random 32-bit value for a decoy segment's sequence/ack fields.
func randSeq32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
