//go:build linux

package packet

import (
	"net"
	"syscall"
)

// disorderTTL is the default TTL for a disorder head segment when none is configured: low enough to
// expire before the server (so the on-path DPI sees an out-of-order ClientHello) yet high enough to
// pass the first few hops where a DPI usually sits.
const disorderTTL = 4

// ttlOpt returns the (level, option) pair for the hop-limit socket option of the connection's
// address family: IP_TTL for IPv4, IPV6_UNICAST_HOPS for IPv6. Using the IPv4 pair on an AF_INET6
// socket fails, which would silently disable disorder on an IPv6 edge.
func (f *fragConn) ttlOpt() (int, int) {
	if ra, ok := f.Conn.RemoteAddr().(*net.TCPAddr); ok && ra.IP.To4() == nil && ra.IP.To16() != nil {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

// writeDisorder sends the HEAD segment at a low TTL so it dies in transit — an on-path DPI ingests
// it but the server never does; the kernel then retransmits it at the normal TTL, so the server
// reassembles the real ClientHello while the DPI saw the segments out of order. It reaches under the
// TLS conn to the raw fd (net.TCPConn.SyscallConn) to set the hop limit per segment; TCP_NODELAY
// (Go's default) makes each Write flush a segment while its TTL is in effect. Falls back to a plain
// split when the raw fd is unavailable.
func (f *fragConn) writeDisorder(p []byte, at int) (int, error) {
	sc, ok := f.Conn.(syscall.Conn)
	if !ok {
		return f.writeSplit(p, at)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return f.writeSplit(p, at)
	}
	level, opt := f.ttlOpt()
	ttl := f.ttl
	if ttl <= 0 {
		ttl = disorderTTL
	}
	orig := 64
	if cerr := raw.Control(func(fd uintptr) {
		if v, e := syscall.GetsockoptInt(int(fd), level, opt); e == nil && v > 0 {
			orig = v
		}
		syscall.SetsockoptInt(int(fd), level, opt, ttl)
	}); cerr != nil {
		return f.writeSplit(p, at) // couldn't touch the socket -> at least split
	}
	n1, werr := f.Conn.Write(p[:at]) // head flushed at the low TTL -> expires before the server
	_ = raw.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), level, opt, orig) // restore for the tail + retransmit
	})
	if werr != nil {
		return n1, werr
	}
	n2, werr := f.Conn.Write(p[at:])
	return n1 + n2, werr
}
