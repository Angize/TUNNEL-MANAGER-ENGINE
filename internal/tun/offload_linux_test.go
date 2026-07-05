//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildTCP4 makes an IPv4/TCP packet with the given payload (checksums valid),
// as the kernel would hand us a TSO super-packet.
func buildTCP4(src, dst [4]byte, seq uint32, flags byte, payload []byte) []byte {
	p := make([]byte, 20+20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 0x1000) // id base
	p[8] = 64
	p[9] = 6 // TCP
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))
	binary.BigEndian.PutUint32(p[24:28], seq)
	p[32] = 5 << 4 // data offset
	p[33] = flags
	binary.BigEndian.PutUint16(p[34:36], 0xffff) // window
	copy(p[40:], payload)
	binary.BigEndian.PutUint16(p[36:38], l4Checksum(p, 20, false, 6))
	return p
}

func buildUDP4(src, dst [4]byte, payload []byte) []byte {
	p := make([]byte, 20+8+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], 51820)                  // UDP src port
	binary.BigEndian.PutUint16(p[22:24], 443)                    // UDP dst port
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload))) // UDP length
	copy(p[28:], payload)                                        // payload after 8-byte UDP header (20+8=28)
	binary.BigEndian.PutUint16(p[26:28], l4Checksum(p, 20, false, 17))
	return p
}

func ipOK(t *testing.T, seg []byte) {
	if fold(sumBytes(seg[:20], 0)) != 0xffff {
		t.Errorf("IPv4 header checksum invalid")
	}
}

func l4OK(t *testing.T, seg []byte, proto byte) {
	off := 16 // TCP checksum offset within L4
	if proto == 17 {
		off = 6
	}
	stored := binary.BigEndian.Uint16(seg[20+off : 20+off+2])
	if stored == 0 && proto == 17 {
		return // UDP checksum optional
	}
	seg[20+off], seg[20+off+1] = 0, 0
	want := l4Checksum(seg, 20, false, proto)
	binary.BigEndian.PutUint16(seg[20+off:], stored)
	if stored != want {
		t.Errorf("L4 (proto %d) checksum = %#x, want %#x", proto, stored, want)
	}
}

func TestSegmentTCP4(t *testing.T) {
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	payload := make([]byte, 4000)
	for i := range payload {
		payload[i] = byte(i)
	}
	const seq0 = 1000
	super := buildTCP4(src, dst, seq0, 0x18 /*PSH|ACK*/, payload)

	segs := segment(super, 1400, true)
	if len(segs) != 3 {
		t.Fatalf("got %d segments, want 3", len(segs))
	}
	var reassembled []byte
	for i, seg := range segs {
		ipOK(t, seg)
		l4OK(t, seg, 6)
		if total := int(binary.BigEndian.Uint16(seg[2:4])); total != len(seg) {
			t.Errorf("seg %d IP total length %d != %d", i, total, len(seg))
		}
		if seq := binary.BigEndian.Uint32(seg[24:28]); seq != uint32(seq0)+uint32(len(reassembled)) {
			t.Errorf("seg %d seq %d, want %d", i, seq, uint32(seq0)+uint32(len(reassembled)))
		}
		last := i == len(segs)-1
		psh := seg[33]&0x08 != 0
		if psh != last {
			t.Errorf("seg %d PSH=%v, want %v (only last)", i, psh, last)
		}
		reassembled = append(reassembled, seg[40:]...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatal("reassembled payload != original")
	}
}

func TestSegmentUDP4(t *testing.T) {
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	super := buildUDP4(src, dst, payload)
	segs := segment(super, 1200, false)
	if len(segs) != 3 {
		t.Fatalf("got %d UDP segments, want 3", len(segs))
	}
	var re []byte
	for i, seg := range segs {
		ipOK(t, seg)
		l4OK(t, seg, 17)
		if ul := int(binary.BigEndian.Uint16(seg[24:26])); ul != 8+len(seg)-28 {
			t.Errorf("seg %d UDP length wrong", i)
		}
		re = append(re, seg[28:]...)
	}
	if !bytes.Equal(re, payload) {
		t.Fatal("reassembled UDP payload != original")
	}
}

func TestSegmentSinglePassThrough(t *testing.T) {
	src, dst := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	super := buildTCP4(src, dst, 1, 0x18, make([]byte, 500))
	segs := segment(super, 1400, true) // one MSS fits -> single segment
	if len(segs) != 1 {
		t.Fatalf("got %d segments, want 1", len(segs))
	}
	ipOK(t, segs[0])
	l4OK(t, segs[0], 6)
}
