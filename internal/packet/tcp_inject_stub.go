//go:build !linux

package packet

import "net"

// sendTCPFakes is a no-op off Linux: the AF_PACKET L2 injection the TCP-inject desync needs is
// Linux-only. The carrier still works; it just emits no decoys.
func (b *TCP) sendTCPFakes(conn net.Conn) {}
