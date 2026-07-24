//go:build linux

package packet

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestPktinfoDst crafts an IP_PKTINFO control message with a known received-destination address
// (ipi_addr) and confirms pktinfoDst extracts it — the "which of our IPs did the client dial" read.
func TestPktinfoDst(t *testing.T) {
	want := net.IPv4(203, 0, 113, 9).To4()
	b := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_IP
	h.Type = unix.IP_PKTINFO
	h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
	copy(pi.Addr[:], want) // ipi_addr = the datagram's destination

	if got := pktinfoDst(b); got == nil || !got.Equal(net.IP(want)) {
		t.Fatalf("pktinfoDst = %v, want %v", got, net.IP(want))
	}
	if d := pktinfoDst(nil); d != nil {
		t.Fatalf("pktinfoDst(nil) = %v, want nil", d)
	}
}

// TestPktinfoOOB confirms pktinfoOOB builds a well-formed IP_PKTINFO cmsg whose ipi_spec_dst carries
// the requested source — the "answer FROM this IP" write.
func TestPktinfoOOB(t *testing.T) {
	src := net.IPv4(198, 51, 100, 7).To4()
	msgs, err := unix.ParseSocketControlMessage(pktinfoOOB(net.IP(src)))
	if err != nil || len(msgs) != 1 {
		t.Fatalf("ParseSocketControlMessage: err=%v msgs=%d", err, len(msgs))
	}
	m := msgs[0]
	if m.Header.Level != unix.IPPROTO_IP || m.Header.Type != unix.IP_PKTINFO {
		t.Fatalf("cmsg level/type = %d/%d, want %d/%d", m.Header.Level, m.Header.Type, unix.IPPROTO_IP, unix.IP_PKTINFO)
	}
	if len(m.Data) < 12 || !net.IP(m.Data[4:8]).Equal(net.IP(src)) { // Inet4Pktinfo: ifindex|spec_dst|addr
		t.Fatalf("spec_dst = %v, want %v", net.IP(m.Data[4:8]), net.IP(src))
	}
	if pktinfoOOB(net.ParseIP("2001:db8::1")) != nil {
		t.Fatalf("pktinfoOOB(IPv6) = non-nil, want nil")
	}
}
