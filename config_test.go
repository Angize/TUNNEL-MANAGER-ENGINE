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
