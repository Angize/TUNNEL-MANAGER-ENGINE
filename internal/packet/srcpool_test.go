package packet

import (
	"net"
	"testing"
)

// TestServerSrcAllowed verifies the pooled-server source admission: a server told the client's source
// pool admits any of those IPs (so a source rotation reaches crypto), rejects unrelated hosts, and a
// non-pool server / client keeps the strict "no extra sources" behaviour.
func TestServerSrcAllowed(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }

	// Flux server with a 3-IP client source pool.
	f := &Flux{isClient: false}
	f.SetPeerSources([]string{"10.0.0.5", "10.0.0.6:0", "10.0.0.7"})
	for _, in := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"} {
		if !f.srcAllowed(ip(in)) {
			t.Errorf("flux: expected %s admitted", in)
		}
	}
	if f.srcAllowed(ip("10.0.0.9")) {
		t.Error("flux: unrelated host 10.0.0.9 must NOT be admitted")
	}

	// A client ignores SetPeerSources (strict filter stays).
	fc := &Flux{isClient: true}
	fc.SetPeerSources([]string{"10.0.0.5"})
	if fc.srcAllowed(ip("10.0.0.5")) {
		t.Error("flux client must ignore SetPeerSources")
	}

	// A non-pool server (empty set) admits nothing extra.
	f0 := &Flux{isClient: false}
	if f0.srcAllowed(ip("10.0.0.5")) {
		t.Error("flux non-pool server must not admit extra sources")
	}

	// Raw mirrors the same behaviour.
	r := &Raw{isClient: false}
	r.SetPeerSources([]string{"10.0.0.5", "10.0.0.7"})
	if !r.srcAllowed(ip("10.0.0.5")) || !r.srcAllowed(ip("10.0.0.7")) {
		t.Error("raw: pool sources must be admitted")
	}
	if r.srcAllowed(ip("10.0.0.9")) {
		t.Error("raw: unrelated host must NOT be admitted")
	}
	r0 := &Raw{isClient: false}
	if r0.srcAllowed(ip("10.0.0.5")) {
		t.Error("raw non-pool server must not admit extra sources")
	}
}
