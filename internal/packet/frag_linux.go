//go:build linux

package packet

import (
	"bytes"
	"net"
	"syscall"
)

// disorderTTL is the default TTL for a disorder/fake head or decoy segment when none is configured:
// low enough to expire before the server (so the on-path DPI, not the server, ingests it) yet high
// enough to pass the first few hops where a DPI usually sits.
const disorderTTL = 4

// fakeTTL is the TTL of the injected fake ClientHello in fake mode: a normal value, because the fake
// is killed at the server by a bad TCP checksum (hop-independent), not by TTL — so it only needs a
// TTL high enough to reach the on-path DPI, which any normal value satisfies.
const fakeTTL = 64

// TCP_REPAIR socket options (stable Linux ABI). They let us READ the connection's current send/recv
// sequence numbers without disturbing it — needed so a fake segment can overlap the real ClientHello
// at the exact sequence a stateful DPI reassembles on. We only read; we never rewind or write.
const (
	optTCPRepair      = 19 // TCP_REPAIR
	optTCPRepairQueue = 20 // TCP_REPAIR_QUEUE
	optTCPQueueSeq    = 21 // TCP_QUEUE_SEQ
	queueRecv         = 1  // TCP_RECV_QUEUE (kernel enum: NO_QUEUE=0, RECV=1, SEND=2)
	queueSend         = 2  // TCP_SEND_QUEUE
)

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

// readSeqs briefly enters TCP_REPAIR mode on the (idle, established) socket at the ClientHello point
// to read the send and receive sequence numbers, then leaves it. Returns ok=false if any step
// fails. Read-only: it never changes a queue's contents or sequence, so it does not disturb the
// connection (this is the CRIU checkpoint path, done here on a connection with no in-flight data).
func readSeqs(raw syscall.RawConn) (snd, rcv uint32, ok bool) {
	_ = raw.Control(func(fd uintptr) {
		f := int(fd)
		if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepair, 1) != nil {
			return
		}
		defer syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepair, 0)
		if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepairQueue, queueSend) != nil {
			return
		}
		s, e1 := syscall.GetsockoptInt(f, syscall.IPPROTO_TCP, optTCPQueueSeq)
		if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepairQueue, queueRecv) != nil {
			return
		}
		r, e2 := syscall.GetsockoptInt(f, syscall.IPPROTO_TCP, optTCPQueueSeq)
		if e1 == nil && e2 == nil {
			snd, rcv, ok = uint32(s), uint32(r), true
		}
	})
	return
}

// writeFake injects a fake ClientHello — a copy of the real one with the SNI overwritten by a decoy
// — as a raw TCP segment at the SAME sequence as the real ClientHello, carrying a deliberately BAD
// TCP checksum so the server's stack drops it. A stateful DPI reassembles the fake (decoy SNI) at
// that sequence and clears the flow; the server discards the fake (bad checksum) and gets the real
// ClientHello, written normally right after (the socket's sequence is untouched, because the fake
// goes out via AF_PACKET, not the socket). Killing by checksum instead of a low TTL is
// hop-independent — it works even when the server is a nearby CDN edge, where no TTL window exists.
// AF_PACKET SOCK_RAW hands the frame to the driver with CHECKSUM_NONE, so TX offload does not repair
// the checksum. This defeats a DPI that reassembles the stream — which plain split/disorder do not.
// IPv4 only (the raw injector builds IPv4); falls back to disorder on IPv6 or when any primitive is
// unavailable. Needs CAP_NET_RAW + CAP_NET_ADMIN, which the core holds (it runs as root).
func (f *fragConn) writeFake(p []byte, at int) (int, error) {
	la, ok1 := f.Conn.LocalAddr().(*net.TCPAddr)
	ra, ok2 := f.Conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return f.writeDisorder(p, at)
	}
	src, dst := la.IP.To4(), ra.IP.To4()
	if src == nil || dst == nil { // IPv6 -> the raw injector can't build it; disorder is the next best
		return f.writeDisorder(p, at)
	}
	sc, ok := f.Conn.(syscall.Conn)
	if !ok {
		return f.writeDisorder(p, at)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return f.writeDisorder(p, at)
	}
	snd, rcv, ok := readSeqs(raw)
	if !ok {
		return f.writeDisorder(p, at)
	}
	inj, err := newL2Inject(ra.IP)
	if err != nil {
		return f.writeDisorder(p, at)
	}
	defer inj.close()
	fake := make([]byte, len(p))
	copy(fake, p)
	if i := bytes.Index(fake, []byte(f.host)); i >= 0 {
		copy(fake[i:i+len(f.host)], decoySNI(len(f.host)))
	}
	seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), snd, rcv, tcpPshAck, 0xffff, fake)
	badTCPChecksum(seg)                                                // the SERVER drops the fake (bad L4 checksum); the DPI still ingests it
	if ip := buildIP4Ext(src, dst, protoTCP, fakeTTL, false, seg); ip != nil { // normal TTL so the fake reaches the DPI; the checksum, not TTL, kills it before the server
		_ = inj.send(ip)
	}
	return f.Conn.Write(p) // the real ClientHello, whole, at the same sequence (socket untouched)
}
