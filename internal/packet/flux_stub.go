//go:build !linux

// flux, like the raw transport, uses Linux raw IPv4 sockets (IP_HDRINCL) and
// AF_PACKET, so off Linux the constructors fail cleanly and the rest of the core
// still builds. The portable shape derivation in flux.go stays available and tested.
package packet

import (
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// Flux is unavailable off Linux; the type exists only so the constructors share a
// signature with the Linux build.
type Flux struct{}

func (f *Flux) Run() error   { return errRawUnsupported }
func (f *Flux) Close() error { return nil }

func DialFlux(string, *tun.Device, time.Duration, time.Duration, bool, bool, string, string) (*Flux, error) {
	return nil, errRawUnsupported
}

func ListenFlux(string, *tun.Device, time.Duration, time.Duration, bool, bool, string, string) (*Flux, error) {
	return nil, errRawUnsupported
}
