//go:build linux

package packet

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestDesyncWireEmission is a real-socket integration check (root-only): it drives the
// actual Raw.SetDesync + sendFakes path over a live IP_HDRINCL socket to the loopback and
// receives the decoys on a raw socket of the same protocol, asserting the kernel
// transmitted exactly `count` decoys carrying the stamped low TTL and a plausible-frame
// payload size. This proves the emission mechanism end to end (openHdrincl + buildIP4Ext +
// Sendto over a real kernel socket), beyond the pure-function unit tests.
func TestDesyncWireEmission(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root (raw sockets / CAP_NET_RAW)")
	}
	const proto = protoBIP
	const ttl = 7
	const count = 3

	// Receiver: a raw socket of our protocol bound to loopback. AF_INET SOCK_RAW hands back
	// the full IP header, so the TTL is readable at byte 8.
	rfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		t.Skipf("cannot open raw receive socket: %v", err)
	}
	defer syscall.Close(rfd)
	if err := syscall.Bind(rfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind receiver: %v", err)
	}
	tv := syscall.Timeval{Sec: 2}
	_ = syscall.SetsockoptTimeval(rfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Sender: the real Raw desync path. SetDesync opens the dedicated fake socket itself
	// (spoofFd is -1 here), so this also exercises that fd-open branch.
	lo := net.IPv4(127, 0, 0, 1)
	r := &Raw{isClient: true, proto: proto, spoofFd: -1, fakeFd: -1, pktFd: -1}
	r.localIP.Store(&net.IPAddr{IP: lo})
	r.SetDesync(true, ttl, count, "ttl") // valid checksum so loopback delivers the decoys
	if !r.desync.on || r.fakeFd < 0 {
		t.Skip("SetDesync could not open the fake socket here")
	}
	defer func() {
		r.sendMu.Lock()
		r.sendDown = true
		r.sendMu.Unlock()
		syscall.Close(r.fakeFd)
	}()

	r.sendFakes(&net.IPAddr{IP: lo})

	buf := make([]byte, 1500)
	seen := 0
	deadline := time.Now().Add(2 * time.Second)
	for seen < count && time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(rfd, buf, 0)
		if err != nil {
			break // SO_RCVTIMEO fired
		}
		if n < 20 || buf[9] != byte(proto) {
			continue
		}
		if buf[8] != ttl {
			t.Fatalf("decoy TTL = %d, want the stamped %d", buf[8], ttl)
		}
		ihl := int(buf[0]&0x0f) * 4
		if payLen := n - ihl; payLen < 48 || payLen > 111 {
			t.Fatalf("decoy payload len %d out of the 48..111 band", payLen)
		}
		seen++
	}
	if seen != count {
		t.Fatalf("received %d decoys on the wire, want %d", seen, count)
	}
}
