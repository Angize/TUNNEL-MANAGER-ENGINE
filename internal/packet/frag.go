package packet

import (
	"bytes"
	"net"
	"sync"
)

// fragConn splits the FIRST write on a connection into two separate writes, so the client's TLS
// ClientHello is sent across two TCP segments and the cleartext SNI lands on the segment boundary.
// An on-path DPI that inspects each packet independently can no longer match the full hostname
// against an SNI blocklist (SNI fragmentation). The real server's TCP stack reassembles the stream,
// so the handshake itself is unaffected. This is a cheap COMPLEMENT to ECH (which hides the SNI
// entirely): it helps where ECH is unavailable, and only against stateless / first-segment DPI (a
// DPI that fully reassembles the TCP stream still recovers the SNI). After the first write the conn
// is a transparent passthrough; every other net.Conn method delegates to the embedded conn.
//
// Separate TCP segments rely on TCP_NODELAY (Go's dialer sets it by default), so the first chunk
// leaves the kernel before the second Write is queued.
type fragConn struct {
	net.Conn
	host string // the SNI we connect with; used to auto-locate the split point (absent under ECH)
	pos  int    // explicit split offset into the first write; 0 = auto (middle of the cleartext hostname)
	mu   sync.Mutex
	sent bool
}

// newFragConn wraps c so its first write is split. host is the SNI (for auto split-point location),
// pos an explicit offset (0 = auto).
func newFragConn(c net.Conn, host string, pos int) *fragConn {
	return &fragConn{Conn: c, host: host, pos: pos}
}

// Write splits only the first call; later writes pass through. The split point is the configured
// offset when > 0, else the middle of the cleartext hostname when it appears in the buffer. If the
// split point is out of range or the hostname isn't in cleartext (e.g. ECH), the buffer is written
// whole — a safe no-op that never corrupts the handshake.
func (f *fragConn) Write(p []byte) (int, error) {
	f.mu.Lock()
	first := !f.sent
	f.sent = true
	f.mu.Unlock()
	if !first {
		return f.Conn.Write(p)
	}
	at := f.splitAt(p)
	if at <= 0 || at >= len(p) {
		return f.Conn.Write(p)
	}
	n1, err := f.Conn.Write(p[:at])
	if err != nil {
		return n1, err
	}
	n2, err := f.Conn.Write(p[at:])
	return n1 + n2, err
}

// splitAt returns the offset in the first write to split at: the configured pos when > 0, else the
// middle of the cleartext hostname if present (0 when there is nothing to split).
func (f *fragConn) splitAt(p []byte) int {
	if f.pos > 0 {
		return f.pos
	}
	if f.host == "" {
		return 0
	}
	i := bytes.Index(p, []byte(f.host))
	if i < 0 {
		return 0 // hostname not in cleartext (ECH, or an unexpected ClientHello layout) -> don't split
	}
	return i + len(f.host)/2
}
