//go:build !linux

package packet

import "syscall"

// Non-linux builds (tests/tooling on dev machines): the FORCE setsockopts are linux-only,
// so these are no-ops. The core only ever runs on linux.
func applyRawConnBuf(rc syscall.RawConn, n int) {}
func applyFdBuf(fd, n int)                       {}
func applyFdSndBuf(fd, n int)                    {}
func applyFdRcvBuf(fd, n int)                    {}
