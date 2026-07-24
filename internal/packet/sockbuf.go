package packet

import (
	"sync/atomic"
	"syscall"
)

// sockBufBytes is the send/receive socket-buffer size pinned on the datagram carriers
// (udp/raw/flux) as their sockets are created. One core process serves one tunnel, so a
// package var set once at startup is safe process-global state (mirrors ApplyTuning).
// <=0 leaves the kernel default (feature off).
var sockBufBytes atomic.Int64

// SetSockBuf records the process-wide datagram socket-buffer target. Called once from main
// after the config is parsed, BEFORE any carrier socket is opened.
func SetSockBuf(n int) { sockBufBytes.Store(int64(n)) }

func wantSockBuf() int { return int(sockBufBytes.Load()) }

// syscallConn is the SyscallConn accessor shared by *net.UDPConn (udp) and *net.IPConn (raw).
type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// applyConnSockBuf sizes a net.Conn socket's send/receive buffers to the configured target.
// Datagram sockets have no kernel autotuning, so on a high-BDP link the default buffer caps
// throughput and drops bursts; this lifts that ceiling. No-op when unconfigured / non-linux.
func applyConnSockBuf(c syscallConn) {
	n := wantSockBuf()
	if n <= 0 || c == nil {
		return
	}
	if rc, err := c.SyscallConn(); err == nil {
		applyRawConnBuf(rc, n)
	}
}
