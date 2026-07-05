//go:build linux

// GSO/GRO offload for the TUN device. When enabled, the interface is opened with
// a virtio-net header and TCP/UDP segmentation offload, so the kernel hands the
// engine ONE large "super-packet" (up to 64 KiB) instead of dozens of MTU-sized
// packets on bulk transfers. readGSO splits that super-packet back into ordinary
// L3 packets in userspace (recomputing every IP/TCP/UDP checksum from scratch,
// which sidesteps the virtio partial-checksum convention entirely), so the rest
// of the engine — and the wire format between the two ends — is unchanged. The
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
	var ipHdrLen int
	if v6 {
		ipHdrLen = 40
	} else {
		ipHdrLen = int(pkt[0]&0x0f) * 4
	}
	if len(pkt) < ipHdrLen+8 {
		return [][]byte{pkt}
	}
	l4Hdr := 8 // UDP
	if isTCP {
		l4Hdr = int(pkt[ipHdrLen+12]>>4) * 4
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
			binary.BigEndian.PutUint16(seg[4:6], uint16(l4Hdr+len(chunk))) // payload length
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
			seg[ipHdrLen+16], seg[ipHdrLen+17] = 0, 0
			binary.BigEndian.PutUint16(seg[ipHdrLen+16:ipHdrLen+18], l4Checksum(seg, ipHdrLen, v6, 6))
		} else {
			binary.BigEndian.PutUint16(seg[ipHdrLen+4:ipHdrLen+6], uint16(8+len(chunk))) // UDP length
			seg[ipHdrLen+6], seg[ipHdrLen+7] = 0, 0
			binary.BigEndian.PutUint16(seg[ipHdrLen+6:ipHdrLen+8], l4Checksum(seg, ipHdrLen, v6, 17))
		}
		out = append(out, seg)
	}
	return out
}

// finalizeCsum recomputes the L4 checksum of a single (non-GSO) packet whose
// checksum the kernel deferred (VIRTIO_NET_HDR_F_NEEDS_CSUM). Rebuilding it from
// scratch avoids depending on the virtio partial-sum sitting in the field.
func finalizeCsum(pkt []byte) {
	v6 := pkt[0]>>4 == 6
	var ipHdrLen int
	var proto byte
	if v6 {
		if len(pkt) < 40 {
			return
		}
		ipHdrLen, proto = 40, pkt[6]
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
		pkt[ipHdrLen+16], pkt[ipHdrLen+17] = 0, 0
		binary.BigEndian.PutUint16(pkt[ipHdrLen+16:ipHdrLen+18], l4Checksum(pkt, ipHdrLen, v6, 6))
	case 17:
		pkt[ipHdrLen+6], pkt[ipHdrLen+7] = 0, 0
		binary.BigEndian.PutUint16(pkt[ipHdrLen+6:ipHdrLen+8], l4Checksum(pkt, ipHdrLen, v6, 17))
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
