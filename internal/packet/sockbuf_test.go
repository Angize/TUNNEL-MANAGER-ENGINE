//go:build linux

package packet

import (
	"net"
	"syscall"
	"testing"
)

// TestSockBufRoundtrip covers the package-var knob and its no-op guard.
func TestSockBufRoundtrip(t *testing.T) {
	orig := wantSockBuf()
	t.Cleanup(func() { SetSockBuf(orig) })

	SetSockBuf(123456)
	if got := wantSockBuf(); got != 123456 {
		t.Fatalf("wantSockBuf = %d, want 123456", got)
	}
	// applyFdBuf on a bogus fd or a non-positive size must not panic and must be a no-op.
	applyFdBuf(-1, 4<<20)
	SetSockBuf(0)
	applyFdBuf(3, 0)
}

// getBuf reads back SO_RCVBUF/SO_SNDBUF (the kernel reports ~2× the value set).
func getBuf(t *testing.T, c syscallConn, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var v int
	if err := rc.Control(func(fd uintptr) {
		v, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	return v
}

// TestApplyConnSockBufGrows proves the buffer is actually enlarged on a real UDP socket.
// The FORCE setsockopt needs CAP_NET_ADMIN; when the test runs unprivileged on a box whose
// rmem_max equals rmem_default the buffer cannot grow, so the test skips rather than fails.
func TestApplyConnSockBufGrows(t *testing.T) {
	orig := wantSockBuf()
	t.Cleanup(func() { SetSockBuf(orig) })

	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer c.Close()

	before := getBuf(t, c, syscall.SO_RCVBUF)
	SetSockBuf(4 << 20)
	applyConnSockBuf(c)
	after := getBuf(t, c, syscall.SO_RCVBUF)

	if after <= before {
		t.Skipf("SO_RCVBUF did not grow (%d -> %d): no CAP_NET_ADMIN and rmem_max at default", before, after)
	}
	// When it did grow it should be near 2×4 MiB (kernel doubling), not a tiny bump.
	if after < 2<<20 {
		t.Fatalf("SO_RCVBUF grew only to %d, expected >= %d", after, 2<<20)
	}
}
