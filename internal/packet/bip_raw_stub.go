//go:build !linux

// The raw transport uses Linux raw IPv4 sockets (CAP_NET_RAW). On other
// platforms the constructors fail cleanly so the rest of the core still builds
// and runs (the raw profile codec in rawprofile.go stays portable and tested).
package packet

import (
	"errors"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// Raw is unavailable off Linux; the type exists only so the constructors share a
// signature with the Linux build.
type Raw struct{}

var errRawUnsupported = errors.New("raw transport requires Linux (raw IPv4 sockets)")

func (r *Raw) Run() error   { return errRawUnsupported }
func (r *Raw) Close() error { return nil }

func DialRaw(string, *tun.Device, time.Duration, bool, bool, string, string, string) (*Raw, error) {
	return nil, errRawUnsupported
}

func ListenRaw(string, *tun.Device, time.Duration, bool, bool, string, string, string) (*Raw, error) {
	return nil, errRawUnsupported
}
