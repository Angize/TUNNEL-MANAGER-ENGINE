package main

import (
	"encoding/json"
	"errors"
	"os"
)

// CryptoCfg controls confidentiality on the wire. When Enabled is false the
// raw L3 packet travels in the clear (useful for debugging or when an outer
// transport already provides TLS). The PSK is used to derive the AEAD key and
// is NEVER echoed back to the panel or node public config.
type CryptoCfg struct {
	Enabled bool   `json:"enabled"`
	PSK     string `json:"psk"`
	Cipher  string `json:"cipher"` // "aes-256-gcm" (default / only for now)
}

// Config is the full contract between the Python node agent and this engine.
// The node writes it to engine-<id>.json and launches the binary with
// --config <path>. Nothing here is invented at runtime; the node owns it.
type Config struct {
	Role    string `json:"role"`    // "server" (public, listens) | "client" (behind NAT, dials)
	Mode    string `json:"mode"`    // "packet" (only mode implemented in this slice)
	Profile string `json:"profile"` // "bip" (only profile implemented in this slice)

	// Transport selects the carrier for bip frames: "udp" (default,
	// NAT-friendly datagrams), "tcp" (stream, length-prefixed frames), or "raw"
	// (each frame in a raw IPv4 packet of a chosen protocol — see Profile).
	Transport string `json:"transport"`

	// RawProfile selects the raw-transport encapsulation (Transport=="raw" only):
	// "bip" (native, proto 253), "ipip" (4), "gre" (47), "icmp" (1), "udp" (17),
	// or "tcp" (6). The sealed frame is identical across profiles; only the
	// IP-layer carrier header — and thus how the traffic looks — changes. Raw
	// sockets need CAP_NET_RAW and Linux; ipip/gre often do not cross NAT.
	RawProfile string `json:"raw_profile"`

	Listen string `json:"listen"` // server: bind address, e.g. "0.0.0.0:9000"
	Peer   string `json:"peer"`   // client: server address, e.g. "1.2.3.4:9000"

	TunName string `json:"tun_name"` // requested interface name, e.g. "tnl0"
	TunAddr string `json:"tun_addr"` // local L3 address with prefix, e.g. "10.200.0.1/24"
	TunPeer string `json:"tun_peer"` // peer L3 address (reference), e.g. "10.200.0.2"
	MTU     int    `json:"mtu"`      // TUN MTU, e.g. 1400

	Keepalive int       `json:"keepalive"` // client ping interval in seconds (default 15)
	Crypto    CryptoCfg `json:"crypto"`

	// Obfs turns on anti-DPI framing: the constant magic byte is dropped, the
	// frame type is folded into the AEAD-sealed plaintext, random padding and
	// keepalive jitter break size/timing fingerprints, and (TCP) the length
	// prefix is masked with a PSK-derived keystream. It requires crypto because
	// the obfuscation and probe resistance both rely on the AEAD key.
	Obfs bool `json:"obfs"`

	// Cover wraps the (TCP) transport in a REALITY-style TLS session that
	// fingerprints as Chrome, so the wire looks like ordinary HTTPS. Our client
	// hides a PSK-authenticated token in its ClientHello; the server terminates
	// TLS for us but transparently proxies every OTHER connection (probes, the
	// censor) to CoverSNI:443, so active probing sees that site's genuine cert.
	// CoverSNI must therefore be a REAL, reachable, unblocked HTTPS site — it is
	// the cover the server borrows. TCP only; bip/PSK runs inside the TLS tunnel.
	Cover    bool   `json:"cover"`
	CoverSNI string `json:"cover_sni"`

	// GSO opens the TUN with a virtio-net header and TCP/UDP segmentation
	// offload, so the kernel hands the engine large super-packets on bulk
	// transfers instead of many MTU-sized ones — fewer syscalls/copies, higher
	// throughput. It is a local optimization only (the wire format is unchanged)
	// and each side can enable it independently. Linux only.
	GSO bool `json:"gso"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.Keepalive == 0 {
		c.Keepalive = 15
	}
	if c.Crypto.Cipher == "" {
		c.Crypto.Cipher = "aes-256-gcm"
	}
	if c.Transport == "" {
		c.Transport = "udp"
	}
	if c.Transport == "raw" && c.RawProfile == "" {
		c.RawProfile = "bip"
	}
}

// rawProfiles is the set of valid raw-transport encapsulation profiles. It
// mirrors the map in the packet package (kept here so config validation does not
// depend on that package).
var rawProfiles = map[string]bool{
	"bip": true, "ipip": true, "gre": true, "icmp": true, "udp": true, "tcp": true,
}

func (c *Config) validate() error {
	if c.Mode != "packet" {
		return errors.New("mode must be \"packet\" in this build")
	}
	if c.Profile != "bip" {
		return errors.New("profile must be \"bip\" in this build")
	}
	switch c.Role {
	case "server":
		if c.Listen == "" {
			return errors.New("server role requires \"listen\"")
		}
	case "client":
		if c.Peer == "" {
			return errors.New("client role requires \"peer\"")
		}
	default:
		return errors.New("role must be \"server\" or \"client\"")
	}
	switch c.Transport {
	case "", "udp", "tcp":
		// ok ("" defaults to udp in applyDefaults)
	case "raw":
		if c.RawProfile != "" && !rawProfiles[c.RawProfile] {
			return errors.New("raw_profile must be one of bip|ipip|gre|icmp|udp|tcp")
		}
		if !c.Crypto.Enabled {
			return errors.New("raw transport requires crypto enabled (the AEAD both encrypts and authenticates each raw packet)")
		}
	default:
		return errors.New("transport must be \"udp\", \"tcp\", or \"raw\"")
	}
	if c.TunAddr == "" {
		return errors.New("tun_addr is required")
	}
	if c.Crypto.Enabled && c.Crypto.PSK == "" {
		return errors.New("crypto enabled but psk is empty")
	}
	if c.Obfs && !c.Crypto.Enabled {
		return errors.New("obfs requires crypto enabled")
	}
	if c.Cover && c.Transport != "tcp" {
		return errors.New("cover (TLS) requires transport \"tcp\"")
	}
	if c.Cover && c.CoverSNI == "" {
		return errors.New("cover (TLS) requires cover_sni (the SNI to present)")
	}
	return nil
}
