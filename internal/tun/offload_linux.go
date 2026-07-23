//go:build linux

// GSO/GRO offload for the TUN device. When enabled, the interface is opened with
// a virtio-net header and TCP/UDP segmentation offload, so the kernel hands the
// core ONE large "super-packet" (up to 64 KiB) instead of dozens of MTU-sized
// packets on bulk transfers. readGSO splits that super-packet back into ordinary
// L3 packets in userspace (recomputing every IP/TCP/UDP checksum from scratch,
// which sidesteps the virtio partial-checksum convention entirely), so the rest
// of the core — and the wire format between the two ends — is unchanged. The
// win is purely fewer TUN read syscalls and copies per byte moved.
package tun

import "encoding/binary"

const (
	iffVnetHdr    = 0x4000
	tunSetOffload = 0x400454d0

	// TUNSETOFFLOAD capability bits.
	tunFCSUM = 0x01
	tunFTSO4 = 0x02
	tunFTSO6 = 0x04

	vnetHdrLen = 10 // sizeof(struct virtio_net_hdr)

	// virtio_net_hdr.gso_type
	gsoNone  = 0
	gsoTCPv4 = 1
	gsoUDP   = 3
	gsoTCPv6 = 4
	gsoECN   = 0x80 // OR'd into gso_type; masked off before dispatch

	// virtio_net_hdr.flags
	vnetNeedsCsum = 0x01
)

// splitGSO turns one virtio super-packet into ordinary L3 packets. gsoSize is the
// segment payload size (MSS). Non-GSO packets return as a single element.
func splitGSO(pkt []byte, gsoSize, gsoType int) [][]byte {
	switch gsoType &^ gsoECN {
	case gsoTCPv4, gsoTCPv6:
		return segment(pkt, gsoSize, true)
	case gsoUDP:
		return segment(pkt, gsoSize, false)
	default:
		return [][]byte{pkt}
	}
}

// segment splits a TCP (isTCP) or UDP super-packet into MTU-sized packets,
// rebuilding each segment's headers and checksums. It supports IPv4 and IPv6.
func segment(pkt []byte, gsoSize int, isTCP bool) [][]byte {
	v6 := pkt[0]>>4 == 6
	var ipHdrLen int // offset at which the L4 header begins
	if v6 {
		// Walk the IPv6 extension-header chain for the TRUE L4 offset; a fixed
		// 40 corrupts (or mis-segments) packets that carry extension headers.
		// On an unrecognized/truncated chain, or an L4 protocol that disagrees
		// with the GSO type, pass the super-packet through unchanged.
		l4Off, proto, ok := ipv6L4Offset(pkt)
		if !ok || (isTCP && proto != 6) || (!isTCP && proto != 17) {
			return [][]byte{pkt}
		}
		ipHdrLen = l4Off
	} else {
		ipHdrLen = int(pkt[0]&0x0f) * 4
	}
	minL4 := 8 // UDP: the fixed 8-byte header
	if isTCP {
		minL4 = 20 // TCP: data-offset (ipHdrLen+12), flags (ipHdrLen+13) and seq all live within the fixed 20 bytes
	}
	if len(pkt) < ipHdrLen+minL4 {
		return [][]byte{pkt}
	}
	l4Hdr := 8 // UDP
	if isTCP {
		l4Hdr = int(pkt[ipHdrLen+12]>>4) * 4
		if l4Hdr < 20 {
			return [][]byte{pkt} // malformed/short TCP data-offset
		}
	}
	hdrLen := ipHdrLen + l4Hdr
	if len(pkt) <= hdrLen || gsoSize <= 0 {
		return [][]byte{pkt}
	}
	payload := pkt[hdrLen:]

	var baseSeq uint32
	var flags byte
	if isTCP {
		baseSeq = binary.BigEndian.Uint32(pkt[ipHdrLen+4 : ipHdrLen+8])
		flags = pkt[ipHdrLen+13]
	}
	var baseID uint16
	if !v6 {
		baseID = binary.BigEndian.Uint16(pkt[4:6])
	}

	var out [][]byte
	for off, i := 0, 0; off < len(payload); off, i = off+gsoSize, i+1 {
		end := off + gsoSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		last := end == len(payload)

		seg := make([]byte, hdrLen+len(chunk))
		copy(seg, pkt[:hdrLen])
		copy(seg[hdrLen:], chunk)

		// ---- L3 ----
		if v6 {
			// Payload length spans everything after the fixed 40-byte IPv6
			// header: extension headers (ipHdrLen-40) + L4 header + data.
			binary.BigEndian.PutUint16(seg[4:6], uint16((ipHdrLen-40)+l4Hdr+len(chunk))) // payload length
		} else {
			binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg))) // total length
			binary.BigEndian.PutUint16(seg[4:6], baseID+uint16(i)) // id (kernel increments)
			seg[10], seg[11] = 0, 0                                // checksum
			binary.BigEndian.PutUint16(seg[10:12], ipChecksum(seg[:ipHdrLen]))
		}

		// ---- L4 ----
		if isTCP {
			binary.BigEndian.PutUint32(seg[ipHdrLen+4:ipHdrLen+8], baseSeq+uint32(off))
			f := flags
			if !last {
				f &^= 0x09 // clear FIN(0x01) and PSH(0x08) on all but the final segment
			}
			seg[ipHdrLen+13] = f
			writeL4Csum(seg, ipHdrLen, v6, 6)
		} else {
			binary.BigEndian.PutUint16(seg[ipHdrLen+4:ipHdrLen+6], uint16(8+len(chunk))) // UDP length
			writeL4Csum(seg, ipHdrLen, v6, 17)
		}
		out = append(out, seg)
	}
	return out
}

// writeL4Csum zeroes the L4 checksum field (offset +16 for TCP proto 6, +6 for UDP proto 17) then
// writes the freshly computed l4Checksum there. Shared by segment() and finalizeCsum().
func writeL4Csum(pkt []byte, ipHdrLen int, v6 bool, proto byte) {
	off := ipHdrLen + 6
	if proto == 6 {
		off = ipHdrLen + 16
	}
	pkt[off], pkt[off+1] = 0, 0
	binary.BigEndian.PutUint16(pkt[off:off+2], l4Checksum(pkt, ipHdrLen, v6, proto))
}

// finalizeCsum recomputes the L4 checksum of a single (non-GSO) packet whose
// checksum the kernel deferred (VIRTIO_NET_HDR_F_NEEDS_CSUM). Rebuilding it from
// scratch avoids depending on the virtio partial-sum sitting in the field.
func finalizeCsum(pkt []byte) {
	v6 := pkt[0]>>4 == 6
	var ipHdrLen int
	var proto byte
	if v6 {
		// Walk the IPv6 extension-header chain for the TRUE L4 offset and final
		// protocol; assuming a fixed 40 writes the checksum at the wrong offset
		// (corrupting the packet) whenever extension headers are present. On an
		// unrecognized/truncated chain, leave the packet unmodified.
		var ok bool
		ipHdrLen, proto, ok = ipv6L4Offset(pkt)
		if !ok {
			return
		}
	} else {
		if len(pkt) < 20 {
			return
		}
		ipHdrLen, proto = int(pkt[0]&0x0f)*4, pkt[9]
	}
	if len(pkt) < ipHdrLen+8 {
		return
	}
	switch proto {
	case 6:
		if len(pkt) < ipHdrLen+18 {
			return
		}
		writeL4Csum(pkt, ipHdrLen, v6, 6)
	case 17:
		writeL4Csum(pkt, ipHdrLen, v6, 17)
	}
}

// ipv6L4Offset walks the IPv6 extension-header chain, starting from the fixed
// header's Next Header field (byte 6), to locate the true L4 header. It returns
// the byte offset of the L4 header and the final protocol number. ok is false
// when the packet is truncated or the chain contains an unrecognized extension
// header; the caller must then leave the packet unmodified rather than write an
// L4 checksum at a guessed offset. Only the standard extension headers are
// recognized: hop-by-hop (0), routing (43), fragment (44, fixed 8 bytes) and
// destination-options (60); anything else is treated as the upper-layer proto.
func ipv6L4Offset(pkt []byte) (l4Off int, proto byte, ok bool) {
	if len(pkt) < 40 {
		return 0, 0, false
	}
	next := pkt[6]
	off := 40
	for {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination-options: [next][len(8-octet units)]...
			if off+2 > len(pkt) {
				return 0, 0, false
			}
			next = pkt[off]
			off += (int(pkt[off+1]) + 1) * 8 // len excludes the first 8 octets
		case 44: // fragment header: fixed 8 bytes
			if off+8 > len(pkt) {
				return 0, 0, false
			}
			next = pkt[off]
			off += 8
		default:
			// Upper-layer protocol (e.g. TCP 6, UDP 17), 59 (no next header),
			// or an unrecognized ext header. The caller only writes a checksum
			// for 6/17, so unsupported chains become a safe pass-through.
			if off > len(pkt) {
				return 0, 0, false
			}
			return off, next, true
		}
	}
}

// ---- checksums (RFC 1071) ----

func sumBytes(b []byte, init uint32) uint32 {
	s := init
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}

// ipChecksum computes the IPv4 header checksum (checksum field must be zero).
func ipChecksum(hdr []byte) uint16 { return ^fold(sumBytes(hdr, 0)) }

// l4Checksum computes the TCP/UDP checksum over the pseudo-header plus the L4
// segment pkt[ipHdrLen:] (whose own checksum field must be zero on entry).
func l4Checksum(pkt []byte, ipHdrLen int, v6 bool, proto byte) uint16 {
	l4 := pkt[ipHdrLen:]
	var s uint32
	if v6 {
		s = sumBytes(pkt[8:40], 0) // src(16)+dst(16)
	} else {
		s = sumBytes(pkt[12:20], 0) // src(4)+dst(4)
	}
	s += uint32(proto)
	s += uint32(len(l4))
	c := ^fold(sumBytes(l4, s))
	if proto == 17 && c == 0 {
		c = 0xffff // UDP: 0 means "no checksum"; use the equivalent 0xffff
	}
	return c
}
