// Portable TCP-segment crafting shared by the raw carrier's protoTCP profile (portable) and the
// Linux-only desync/inject paths. It lived in tcp_inject_linux.go (//go:build linux) but rawEncap in
// the untagged rawprofile.go builds the identical segment, so the helper moved here (no build tag) to
// serve both without duplication. Depends only on net / encoding/binary / l4Checksum — all portable.
package packet

import (
	"encoding/binary"
	"net"
)

// tcpPshAck is the TCP flag byte for a PSH|ACK segment — what an ordinary data segment carries,
// so a decoy looks like flow data to a DPI.
const tcpPshAck = 0x18

// buildTCPSeg crafts one TCP segment with parameterised ports/seq/ack/flags/window and a correct
// checksum over the IPv4 pseudo-header. The raw carrier calls it with its fixed ports; the desync
// injector calls it on a real connection's 4-tuple to forge a decoy.
func buildTCPSeg(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	h := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint32(h[4:8], seq)
	binary.BigEndian.PutUint32(h[8:12], ack)
	h[12] = 5 << 4 // data offset = 5 words (20 bytes), no options
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:16], window)
	copy(h[20:], payload)
	// checksum field (h[16:18]) is still zero here, as l4Checksum requires
	binary.BigEndian.PutUint16(h[16:18], l4Checksum(src, dst, protoTCP, h))
	return h
}
