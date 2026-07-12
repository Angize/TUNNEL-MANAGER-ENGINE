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
