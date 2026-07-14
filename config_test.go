package main

import "testing"

// validRaw returns a minimal, valid raw-transport client config to mutate in tests.
func validRaw() *Config {
	return &Config{
		Role:      "client",
		Mode:      "packet",
		Profile:   "core", // core profile (distinct from the raw encapsulation)
		Transport: "raw",
		Peer:      "203.0.113.9",
		TunAddr:   "10.200.0.2/24",
		Crypto:    CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
	}
}

func TestRawTransportValidAndDefaults(t *testing.T) {
	c := validRaw()
	if err := c.validate(); err != nil {
		t.Fatalf("valid raw config rejected: %v", err)
	}
	c.applyDefaults()
	if c.RawProfile != "bip" {
		t.Errorf("raw_profile default = %q, want bip", c.RawProfile)
	}
}

func TestRawTransportProfiles(t *testing.T) {
	for _, p := range []string{"bip", "ipip", "gre", "icmp", "udp", "tcp"} {
		c := validRaw()
		c.RawProfile = p
		if err := c.validate(); err != nil {
			t.Errorf("raw_profile %q rejected: %v", p, err)
		}
	}
	c := validRaw()
	c.RawProfile = "wireguard"
	if err := c.validate(); err == nil {
		t.Error("bogus raw_profile accepted")
	}
}

func TestRawTransportRequiresCrypto(t *testing.T) {
	c := validRaw()
	c.Crypto = CryptoCfg{Enabled: false}
	if err := c.validate(); err == nil {
		t.Error("raw transport without crypto was accepted")
	}
}

func TestRawTransportRejectsCover(t *testing.T) {
	c := validRaw()
	c.Cover = true
	c.CoverSNI = "example.com"
	if err := c.validate(); err == nil {
		t.Error("cover was accepted on the raw transport (it is TCP-only)")
	}
}

func TestSpoofValidation(t *testing.T) {
	c := validRaw()
	c.SpoofSrc = "192.0.2.7"
	if err := c.validate(); err != nil {
		t.Errorf("valid spoof_src_ip rejected: %v", err)
	}
	c = validRaw()
	c.SpoofSrc = "not-an-ip"
	if err := c.validate(); err == nil {
		t.Error("bogus spoof_src_ip accepted")
	}
	c = validRaw()
	c.RawProfile = "gre"
	c.SpoofSrc = "192.0.2.7"
	if err := c.validate(); err == nil {
		t.Error("spoofing accepted on a non-bip profile")
	}
	c = validRaw()
	c.RealPeer = "198.51.100.9"
	if err := c.validate(); err != nil {
		t.Errorf("valid real_peer_ip rejected: %v", err)
	}

	// spoof_dst_ip (decoy): valid on a client, rejected when malformed or on a non-bip profile.
	c = validRaw()
	c.SpoofDst = "185.51.200.10"
	if err := c.validate(); err != nil {
		t.Errorf("valid spoof_dst_ip rejected: %v", err)
	}
	c = validRaw()
	c.SpoofDst = "nope"
	if err := c.validate(); err == nil {
		t.Error("bogus spoof_dst_ip accepted")
	}
	c = validRaw()
	c.RawProfile = "udp"
	c.SpoofDst = "185.51.200.10"
	if err := c.validate(); err == nil {
		t.Error("spoof_dst_ip accepted on a non-bip profile")
	}
	// A decoy server must know the client's real IP to reply to (real_peer_ip).
	c = validRaw()
	c.Role = "server"
	c.Listen = "0.0.0.0:9000"
	c.Peer = ""
	c.SpoofDst = "185.51.200.10"
	if err := c.validate(); err == nil {
		t.Error("spoof_dst_ip on a server without real_peer_ip accepted")
	}
	c.RealPeer = "198.51.100.9"
	if err := c.validate(); err != nil {
		t.Errorf("decoy server with real_peer_ip rejected: %v", err)
	}
}

// TestWSPoolNoHost guards the regression where a rotating edge pool (which carries
// its own per-SNI hosts) was rejected because ws_host was empty — the same check
// that must still fire for a single-edge wss client.
func TestWSPoolNoHost(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true,
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	// A pool with no ws_host must be ACCEPTED (the SNI list supplies the hosts).
	c := base()
	c.WSEdgeIPs = []string{"104.16.0.1:443"}
	c.WSEdgeSNIs = []WSSNI{{Host: "cdn.example.com"}}
	if err := c.validate(); err != nil {
		t.Fatalf("ws edge pool without ws_host rejected: %v", err)
	}
	// A single-edge wss client with no ws_host and no pool must still be REJECTED.
	c = base()
	if err := c.validate(); err == nil {
		t.Error("single-edge wss client without ws_host was accepted")
	}
}

// TestWSEdgeIPsValidated locks in that ws_edge_ips are validated as literal ip:port like every other
// rotation pool — a hostname or a portless entry must be rejected at config load, not silently reach
// the data plane (where the pool dials the raw string with no DNS and the edge just burns).
func TestWSEdgeIPsValidated(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
			Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true,
			WSEdgeSNIs: []WSSNI{{Host: "cdn.example.com"}},
			Crypto:     CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	if c := base(); func() bool { c.WSEdgeIPs = []string{"104.16.0.1:443", "104.17.0.1:443"}; return c.validate() != nil }() {
		t.Error("valid ip:port ws_edge_ips rejected")
	}
	c := base()
	c.WSEdgeIPs = []string{"cdn.example.com:443"} // hostname — the pool dials IPs directly, no DNS
	if err := c.validate(); err == nil {
		t.Error("ws_edge_ips with a hostname was accepted")
	}
	c = base()
	c.WSEdgeIPs = []string{"104.16.0.1"} // missing the port
	if err := c.validate(); err == nil {
		t.Error("ws_edge_ips without a port was accepted")
	}
}

// TestListenIPsValidated checks that a pooled server's listen_ips must each be a literal IP:port —
// a hostname, a missing port, or an out-of-range port is rejected at load (we bind these directly).
func TestListenIPsValidated(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "server", Mode: "packet", Profile: "core", Transport: "udp",
			Listen: "0.0.0.0:9000", TunAddr: "10.200.0.1/24",
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	c := base()
	c.ListenIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	if err := c.validate(); err != nil {
		t.Errorf("valid ip:port listen_ips rejected: %v", err)
	}
	c = base()
	c.ListenIPs = []string{"host.example.com:9000"} // hostname — a bind needs a literal IP
	if err := c.validate(); err == nil {
		t.Error("listen_ips with a hostname was accepted")
	}
	c = base()
	c.ListenIPs = []string{"203.0.113.9"} // missing the port
	if err := c.validate(); err == nil {
		t.Error("listen_ips without a port was accepted")
	}
	c = base()
	c.ListenIPs = []string{"203.0.113.9:70000"} // port out of range
	if err := c.validate(); err == nil {
		t.Error("listen_ips with an out-of-range port was accepted")
	}
}

// TestFluxRotateHonoursTunedDefault checks that a flux tunnel with no explicit epoch length resolves
// FluxRotateSecs from the tuned global default (bounded), and falls back to 600 when the knob is unset.
func TestFluxRotateHonoursTunedDefault(t *testing.T) {
	base := func() *Config {
		return &Config{
			Role: "client", Mode: "packet", Profile: "core", Transport: "flux",
			Peer: "203.0.113.9:9000", TunAddr: "10.200.0.2/24",
			Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		}
	}
	c := base() // no tuning -> default 600
	c.applyDefaults()
	if c.FluxRotateSecs != 600 {
		t.Errorf("unset flux rotate should default to 600, got %d", c.FluxRotateSecs)
	}
	c = base()
	c.Tuning = &TuningCfg{FluxRotateDefSecs: 1200}
	c.applyDefaults()
	if c.FluxRotateSecs != 1200 {
		t.Errorf("flux rotate should honour the tuned default 1200, got %d", c.FluxRotateSecs)
	}
	c = base()
	c.Tuning = &TuningCfg{FluxRotateDefSecs: 999999} // absurd -> clamped to the 86400 ceiling
	c.applyDefaults()
	if c.FluxRotateSecs != 86400 {
		t.Errorf("an over-large tuned flux default should clamp to 86400, got %d", c.FluxRotateSecs)
	}
	c = base()
	c.FluxRotateSecs = 42 // an explicit value is never overridden by the default
	c.applyDefaults()
	if c.FluxRotateSecs != 42 {
		t.Errorf("an explicit flux rotate must be preserved, got %d", c.FluxRotateSecs)
	}
}

// validUDP is a minimal valid udp-transport client config to mutate in peer-pool tests.
func validUDP() *Config {
	return &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "udp",
		Peer: "203.0.113.9:9000", TunAddr: "10.200.0.2/24",
		Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
	}
}

func TestPeerPoolUDPValidAndSeedsPeer(t *testing.T) {
	c := validUDP()
	c.Peer = "" // the pool alone must satisfy the client "peer" requirement
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid udp peer pool rejected: %v", err)
	}
	c.applyDefaults()
	if c.Peer != "203.0.113.9:9000" {
		t.Errorf("applyDefaults should seed peer from the first pool entry, got %q", c.Peer)
	}
	// The pool is authoritative: a Peer that disagrees with PeerIPs[0] must be OVERRIDDEN to the
	// pool's starting endpoint, so the initial dial and the pool's cur=0 can't desync.
	c = validUDP()
	c.Peer = "198.51.100.7:9000" // deliberately != PeerIPs[0]
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.applyDefaults()
	if c.Peer != "203.0.113.9:9000" {
		t.Errorf("pool must override a mismatched peer to PeerIPs[0], got %q", c.Peer)
	}
}

func TestPeerPoolUDPEntryNeedsPort(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9", "198.51.100.7:9000"} // first entry missing the port
	if err := c.validate(); err == nil {
		t.Error("udp peer_ips entry without a port was accepted")
	}
}

func TestPeerPoolUDPRejectsHostname(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"cdn.example.com:9000"} // the pool dials IPs directly, no DNS
	if err := c.validate(); err == nil {
		t.Error("udp peer_ips entry with a hostname was accepted")
	}
}

func TestPeerPoolRawAcceptsBareIPRejectsV6(t *testing.T) {
	c := validRaw()
	c.PeerIPs = []string{"203.0.113.9", "198.51.100.7"} // raw addresses a bare IPv4
	if err := c.validate(); err != nil {
		t.Fatalf("valid raw peer pool (bare IPv4) rejected: %v", err)
	}
	// raw/flux are IPv4-only (parseIP4 rejects v6) — an IPv6 entry must be a clean config error,
	// not a silently-skipped endpoint at rotation time.
	c = validRaw()
	c.PeerIPs = []string{"2001:db8::1"}
	if err := c.validate(); err == nil {
		t.Error("raw peer_ips entry with an IPv6 address was accepted")
	}
}

func TestPeerPoolRejectedOnWSAndServer(t *testing.T) {
	// ws has its own edge pool; peer_ips is meaningless there.
	c := &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
		Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
		Crypto:  CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		PeerIPs: []string{"203.0.113.9:443", "198.51.100.7:443"},
	}
	if err := c.validate(); err == nil {
		t.Error("peer_ips on the ws transport was accepted")
	}
	// A server listens; it never dials a pool.
	c = validUDP()
	c.Role = "server"
	c.Listen = "0.0.0.0:9000"
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	if err := c.validate(); err == nil {
		t.Error("peer_ips on a server was accepted")
	}
}

func TestPeerRotateSecsNonNegative(t *testing.T) {
	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.PeerRotateSecs = -5
	if err := c.validate(); err == nil {
		t.Error("negative peer_rotate_secs was accepted")
	}
}

func TestSrcIPsValidation(t *testing.T) {
	// Valid source pool (bare IPv4) on a direct client — accepted alongside a dest pool.
	c := validUDP()
	c.PeerIPs = []string{"203.0.113.9:9000", "198.51.100.7:9000"}
	c.SrcIPs = []string{"192.0.2.10", "192.0.2.11"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid src_ips pool rejected: %v", err)
	}
	// A source is a bare IPv4 regardless of carrier — "ip:port" host must still be an IP, v6 rejected.
	c = validUDP()
	c.SrcIPs = []string{"2001:db8::1"}
	if err := c.validate(); err == nil {
		t.Error("src_ips with an IPv6 address was accepted")
	}
	// Meaningless on ws (own edge pool) and on a server (it does not dial).
	c = &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
		Peer: "203.0.113.9", TunAddr: "10.200.0.2/24", WSTLS: true, WSHost: "cdn.example.com",
		Crypto: CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		SrcIPs: []string{"192.0.2.10", "192.0.2.11"},
	}
	if err := c.validate(); err == nil {
		t.Error("src_ips on the ws transport was accepted")
	}
	c = validUDP()
	c.Role = "server"
	c.Listen = "0.0.0.0:9000"
	c.SrcIPs = []string{"192.0.2.10", "192.0.2.11"}
	if err := c.validate(); err == nil {
		t.Error("src_ips on a server was accepted")
	}
}
