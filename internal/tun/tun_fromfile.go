package tun

import "os"

// FromFile wraps an already-open file descriptor as a Device WITHOUT running any
// `ip` configuration. It exists so the data-plane (packet.UDP / packet.TCP)
// can be driven end-to-end in tests over a socketpair standing in for the TUN,
// on hosts where /dev/net/tun or iproute2 is unavailable. Not used in production.
func FromFile(f *os.File, name string) *Device {
	return &Device{f: f, Name: name}
}
