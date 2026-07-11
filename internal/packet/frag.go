package packet

import (
	"bytes"
	"net"
	"sync"
	"time"
)

// SNI-fragmentation modes.
const (
	// sniSplitMode sends the ClientHello as two IN-ORDER TCP segments split inside the SNI, so no
	// single packet holds the full hostname. Beats a stateless / first-segment DPI, but a DPI that
	// fully reassembles the TCP stream still recovers the SNI.
	sniSplitMode = "split"
	// sniDisorderMode additionally sends the HEAD segment at a low TTL so it expires in transit: an
	// on-path DPI ingests it (out of order, since the tail arrives first with a higher sequence) but
	// the server never sees that copy. The kernel retransmits the head at the normal TTL, so the
	// server still reassembles the real ClientHello. This desyncs a reassembling DPI's view — the
	// zapret/GoodbyeDPI "disorder" idea — at the cost of one retransmit (~RTO) on connect.
	sniDisorderMode = "disorder"
	// sniFakeMode injects a whole FAKE ClientHello (real one with the SNI overwritten by a benign
	// decoy) as a raw segment at the SAME sequence as the real one, with a corrupt TCP checksum so
	// the server drops it. A reassembling DPI resolves the overlap to the decoy SNI and clears the
	// flow; the server discards the fake (bad checksum) and gets the real ClientHello. Killing by
	// checksum is hop-independent, so unlike disorder it works even when the server is a nearby CDN
	// edge. This is the technique that beats a DPI which reassembles the stream (which plain split and
	// disorder do not). Linux + IPv4; falls back to disorder otherwise.
	sniFakeMode = "fake"
)

// fragGap separates the two segments so TCP_NODELAY (set by Go's dialer) reliably emits them as two
// packets instead of coalescing them into one. Paid once, on the first write of a connection.
const fragGap = 1 * time.Millisecond

// fragConn splits the FIRST write on a connection so the client's TLS ClientHello is sent across two
// TCP segments and the cleartext SNI lands on the segment boundary. A cheap complement to ECH (which
// hides the SNI entirely). After the first write the conn is a transparent passthrough; every other
// net.Conn method delegates to the embedded conn.
type fragConn struct {
	net.Conn
	host string // the SNI we connect with; used to auto-locate the split point (absent under ECH)
	pos  int    // explicit split offset into the first write; 0 = auto (middle of the cleartext hostname)
	mode string // "split" | "disorder"
	ttl  int    // disorder: TTL for the head segment (0 = default); low enough to die before the server
	mu   sync.Mutex
	sent bool
}

// newFragConn wraps c so its first write is split. host is the SNI (for auto split-point location),
// pos an explicit offset (0 = auto), mode the fragmentation mode, ttl the disorder head-segment TTL.
func newFragConn(c net.Conn, host string, pos int, mode string, ttl int) *fragConn {
	if mode == "" {
		mode = sniSplitMode
	}
	return &fragConn{Conn: c, host: host, pos: pos, mode: mode, ttl: ttl}
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
	switch f.mode {
	case sniDisorderMode:
		return f.writeDisorder(p, at) // linux: low-TTL head; stub: plain split
	case sniFakeMode:
		return f.writeFake(p, at) // linux: overlapping decoy-SNI ClientHello; stub: plain split
	}
	return f.writeSplit(p, at)
}

// writeSplit sends the buffer as two in-order TCP segments, with a small gap so a TCP_NODELAY socket
// does not coalesce them into a single segment.
func (f *fragConn) writeSplit(p []byte, at int) (int, error) {
	n1, err := f.Conn.Write(p[:at])
	if err != nil {
		return n1, err
	}
	time.Sleep(fragGap)
	n2, err := f.Conn.Write(p[at:])
	return n1 + n2, err
}

// badTCPChecksum corrupts the TCP checksum of an IPv4 TCP segment (the checksum field is bytes 16-17
// of the TCP header) so the SERVER's stack drops the segment — a hop-distance-independent way to make
// the fake ClientHello die before the server while an on-path DPI (which usually does not verify the
// TCP checksum) still ingests it. Routers operate at L3 and never touch the L4 checksum, so a bad TCP
// checksum survives all the way to the server — unlike a bad IP checksum, which a TTL-decrementing
// router recomputes and "repairs". This is why fake mode kills its decoy by checksum, not by TTL:
// TTL needs the fake to die between the DPI and the server, a window that may not exist when the
// server is a nearby CDN edge.
func badTCPChecksum(seg []byte) {
	if len(seg) < 18 {
		return
	}
	seg[16] ^= 0xff // flip the high checksum byte -> guaranteed to differ from the correct checksum
}

// decoySNI returns n benign hostname bytes to overwrite the real SNI in the fake ClientHello — a
// name a censor never blocks (the CDN's own domain), repeated/truncated so the SNI length field in
// the record stays valid.
func decoySNI(n int) []byte {
	const base = "www.cloudflare.com"
	out := make([]byte, n)
	for i := range out {
		out[i] = base[i%len(base)]
	}
	return out
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
