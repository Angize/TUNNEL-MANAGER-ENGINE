package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
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

// Config is the full contract between the Python node agent and this core.
// The node writes it to core-<id>.json and launches the binary with
// --config <path>. Nothing here is invented at runtime; the node owns it.
// WSSNI is one fronting domain in the ws edge pool, with its own base64 ECHConfigList
// (empty = no ECH for this domain) and request path (empty = "/").
type WSSNI struct {
	Host string `json:"host"`
	ECH  string `json:"ech"`
	Path string `json:"path"`
}

type Config struct {
	Role    string `json:"role"`    // "server" (public, listens) | "client" (behind NAT, dials)
	Mode    string `json:"mode"`    // "packet" (only mode implemented in this slice)
	Profile string `json:"profile"` // "core" (the core profile identifier)

	// Transport selects the carrier for bip frames: "udp" (default,
	// NAT-friendly datagrams), "tcp" (stream, length-prefixed frames), "raw"
	// (each frame in a raw IPv4 packet of a chosen protocol — see Profile), or
	// "flux" (a polymorphic raw carrier whose IP protocol rotates every epoch on a
	// clock-derived schedule both ends compute with no wire signal — see FluxRotateSecs).
	Transport string `json:"transport"`

	// RawProfile selects the raw-transport encapsulation (Transport=="raw" only):
	// "bip" (native, proto 253), "ipip" (4), "gre" (47), "icmp" (1), "udp" (17),
	// or "tcp" (6). The sealed frame is identical across profiles; only the
	// IP-layer carrier header — and thus how the traffic looks — changes. Raw
	// sockets need CAP_NET_RAW and Linux; ipip/gre often do not cross NAT.
	RawProfile string `json:"raw_profile"`

	// SpoofSrc (client) forges the outer IPv4 source address of raw-transport packets
	// so per-source/stateful egress filters can't pin the real IP. SpoofPeer (server)
	// is the client's REAL IP: with a forged source the server cannot learn where to
	// reply, so it is told here (the AEAD still authenticates every frame). Raw + bip +
	// crypto only; needs CAP_NET_RAW. Both empty = no spoofing.
	SpoofSrc  string `json:"spoof_src_ip"`
	SpoofPeer string `json:"spoof_peer"`

	// SpoofDst forges the outer IPv4 DESTINATION to a decoy IP (e.g. a reachable,
	// unfiltered host) so an on-path censor sees traffic to the decoy, not to the real
	// server. Both ends carry the same decoy: the client puts it in the header dst while
	// still routing to the real server; the server therefore cannot receive on an ordinary
	// AF_INET raw socket (the kernel drops packets whose dst isn't local) and instead reads
	// with AF_PACKET, and replies with the decoy as the source. A server using SpoofDst
	// must also set SpoofPeer (the forged source hides the client's real IP). Raw + bip +
	// crypto only; needs CAP_NET_RAW. Empty = no destination spoofing.
	SpoofDst string `json:"spoof_dst_ip"`

	Listen string `json:"listen"` // server: bind address, e.g. "0.0.0.0:9000"
	Peer   string `json:"peer"`   // client: server address, e.g. "1.2.3.4:9000"
	// BindIP is the source IP the client dials FROM (its own node IP). On a host with
	// several IPs the kernel would otherwise egress from the primary IP; binding pins the
	// outbound socket to this node's registered IP so the peer/CDN sees the expected source.
	// Empty = let the kernel choose. TCP-family carriers only (tcp/ws/xhttp).
	BindIP string `json:"bind_ip"`

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

	// WebSocket carrier (Transport=="ws"): the bip stream rides RFC 6455 binary
	// frames after an HTTP Upgrade, so it can be fronted through a CDN. WSHost is the
	// Host header (and TLS SNI) — the fronting/origin domain; WSPath the request path
	// ("/" default); WSTLS makes the client speak wss:// (standard TLS to the CDN edge)
	// before the upgrade. The server stays plain (the CDN terminates TLS and forwards
	// the WebSocket to the origin). TCP-family; obfs/crypto apply as with tcp.
	WSHost string `json:"ws_host"`
	WSPath string `json:"ws_path"`
	WSTLS  bool   `json:"ws_tls"`
	// WSXHTTP switches the ws carrier from a WebSocket upgrade to the xhttp mode (a
	// GET-down + POST-up HTTP request pair), which passes CDNs that block WebSocket.
	// Same fronting fields (ws_host/ws_tls/ws_ech/ws_path). Not combined with the pool.
	WSXHTTP bool `json:"ws_xhttp"`
	// WSXHTTPMode picks the xhttp upstream style. "packet" (default) is packet-up: each
	// write is a short discrete POST — the most CDN-compatible, since a CDN that buffers
	// request bodies still forwards short complete POSTs at once. "grpc" is a single
	// full-duplex request wrapped as a real gRPC stream (Content-Type application/grpc +
	// gRPC message framing): a CDN like Cloudflare connects to the origin with h2c and
	// streams the gRPC call instead of buffering it, which is what makes a full-duplex
	// stream survive the CDN->origin leg (needs ws_tls). "stream" is a legacy alias for
	// "grpc" (plain stream-one was removed — it stalled through buffering CDNs). Only
	// meaningful when ws_xhttp is set; the server auto-detects the client's style per
	// request (and serves h2c so the CDN can reach it over HTTP/2).
	WSXHTTPMode string `json:"ws_xhttp_mode"`
	// WSECH is a base64 ECHConfigList (draft-ietf-tls-esni / RFC 9460 HTTPS-record
	// "ech="). On a wss client it encrypts the real SNI (WSHost) inside the ClientHello,
	// leaving only a benign public name on the wire — so an SNI-blocklisting censor
	// cannot tell which domain is being reached and must block the whole CDN IP range
	// (collateral cost) to stop it. The node fetches this from the domain's HTTPS DNS
	// record over DoH (ordinary DNS is often poisoned). Empty = no ECH.
	WSECH string `json:"ws_ech"`

	// WSEdgeIPs / WSEdgeSNIs form a rotation POOL for the ws client: the core cycles
	// (edge-IP × SNI) combinations so no single IP or domain stays exposed long enough
	// to be fingerprinted, and drops a blocked one from rotation. Each SNI carries its
	// own ECH + path. When WSEdgeIPs is non-empty the pool overrides the single
	// WSHost/WSECH/peer. WSRotateSecs is the proactive rotation interval in seconds
	// (0 = rotate only on failure). WSAutoBurn drops a failing IP/SNI from rotation
	// (dial-timeout ⇒ IP, TLS-reset/403 ⇒ SNI) and records it to the status file.
	WSEdgeIPs    []string `json:"ws_edge_ips"`
	WSEdgeSNIs   []WSSNI  `json:"ws_edge_snis"`
	WSRotateSecs int      `json:"ws_rotate_secs"`
	WSAutoBurn   bool     `json:"ws_auto_burn"`
	// WSStatusPath is where the pool writes its live status (active edge + burned
	// IP/SNI lists) so the node/panel can surface and persist auto-burns. Set by main.
	WSStatusPath string `json:"ws_status_path"`

	// FluxCarrier selects how "flux" frames ride the wire: "udp" (default) sends
	// real UDP datagrams on protocol 17 whose ports rotate each epoch among common
	// QUIC/STUN/WebRTC ports — internet-safe, since transit forwards UDP; "stun"
	// additionally wraps every frame in a real STUN Binding header on STUN/TURN
	// ports, so the flow parses as WebRTC signalling; "raw" rotates the IP protocol
	// number itself among an experimental pool, which is stealthier but only survives
	// where those protocols reach the peer (same-segment / L2-adjacent / a cooperative
	// datacenter), not across the open internet. Empty defaults to "udp".
	FluxCarrier string `json:"flux_carrier"`

	// FluxShape is the statistical size profile the carrier mimics: "random"
	// (default), "quic", "video", or "webrtc". It shapes the padding budget of small
	// control frames (keepalives) — the most fingerprintable fixed-size packets — so
	// their size histogram resembles the mimicked traffic. Coarse shaping only: it
	// adds no latency and no MTU cost.
	FluxShape string `json:"flux_shape"`

	// FluxEpochOffset manually advances the shape epoch ("rotate now"): the effective
	// epoch is floor(unixtime / FluxRotateSecs) + FluxEpochOffset. Both ends must
	// carry the same offset (the panel sets it on both on a "rotate now"), which moves
	// the target fleet-wide with no wire signal. 0 = follow the clock only.
	FluxEpochOffset int64 `json:"flux_epoch_offset"`

	// FluxRotateSecs is the epoch length for the "flux" transport: every
	// floor(unixtime / FluxRotateSecs) the carrier shape (protocol/ports and the
	// padding budget, later size/timing) rotates. Both ends derive the shape from
	// HKDF(PSK, epoch) off their own clocks, so rotation needs NO packet on the
	// wire; a few-epoch grace window absorbs clock skew. 0 defaults to 600.
	FluxRotateSecs int `json:"flux_rotate_secs"`

	// Fec turns on forward error correction on the datagram carriers (flux
	// udp/stun/raw). Data frames are grouped into blocks of FecData shards and
	// FecParity parity shards are sent alongside; the receiver reconstructs up to
	// FecParity lost shards per block WITHOUT a retransmit, so a throttled/high-loss
	// link stays usable instead of collapsing the inner TCP with retransmits. It
	// costs FecParity/FecData extra bandwidth. Both ends must match (the panel sets
	// both). It has no effect on the tcp/ws carriers (TCP is already reliable).
	Fec bool `json:"fec"`

	// FecData / FecParity are the block geometry: FecData data shards per block,
	// FecParity parity shards. E.g. 10/3 = "10 + 3" (30% overhead, recovers up to 3
	// of every 13). Defaults 10/3 when Fec is on. Constraint: FecData>=1, FecParity>=1,
	// FecData+FecParity<=255.
	FecData   int `json:"fec_data"`
	FecParity int `json:"fec_parity"`

	// GSO opens the TUN with a virtio-net header and TCP/UDP segmentation
	// offload, so the kernel hands the core large super-packets on bulk
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
	if c.Transport == "flux" {
		if c.FluxRotateSecs == 0 {
			c.FluxRotateSecs = 600
		}
		if c.FluxCarrier == "" {
			c.FluxCarrier = "udp"
		}
	}
	if c.Fec { // FEC defaults apply on any datagram carrier that has it enabled
		if c.FecData == 0 {
			c.FecData = 10
		}
		if c.FecParity == 0 {
			c.FecParity = 3
		}
	}
	if c.Transport == "ws" && c.WSPath == "" {
		c.WSPath = "/"
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
	if c.Profile != "core" {
		return errors.New("profile must be \"core\" in this build")
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
	if c.BindIP != "" && net.ParseIP(c.BindIP) == nil {
		return errors.New("bind_ip must be a valid IP address")
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
		if (c.SpoofSrc != "" || c.SpoofPeer != "" || c.SpoofDst != "") && c.RawProfile != "" && c.RawProfile != "bip" {
			return errors.New("IP spoofing is only supported on the raw \"bip\" profile for now")
		}
		if c.SpoofSrc != "" && net.ParseIP(c.SpoofSrc).To4() == nil {
			return errors.New("spoof_src_ip must be an IPv4 address")
		}
		if c.SpoofPeer != "" && net.ParseIP(c.SpoofPeer).To4() == nil {
			return errors.New("spoof_peer must be an IPv4 address")
		}
		if c.SpoofDst != "" && net.ParseIP(c.SpoofDst).To4() == nil {
			return errors.New("spoof_dst_ip must be an IPv4 address")
		}
		// A server that expects decoy-destination packets receives them via AF_PACKET and
		// replies with the decoy as source, so it can never learn the client's real address
		// from the wire — SpoofPeer must supply it.
		if c.SpoofDst != "" && c.Role == "server" && c.SpoofPeer == "" {
			return errors.New("spoof_dst_ip on a server requires spoof_peer (the client's real IP to reply to)")
		}
	case "flux":
		// The polymorphic carrier rides raw sockets and rotates its protocol from
		// the AEAD-shared key; without crypto there is no key to derive a shape from
		// and no authentication for the shape-independent decode.
		if !c.Crypto.Enabled {
			return errors.New("flux transport requires crypto enabled (the shape is derived from the PSK and the AEAD authenticates every frame)")
		}
		if c.FluxRotateSecs < 0 {
			return errors.New("flux_rotate_secs must be >= 0 (0 defaults to 600)")
		}
		switch c.FluxCarrier {
		case "", "udp", "raw", "stun":
		default:
			return errors.New("flux_carrier must be \"udp\", \"stun\", or \"raw\"")
		}
		switch c.FluxShape {
		case "", "random", "quic", "video", "webrtc":
		default:
			return errors.New("flux_shape must be \"random\", \"quic\", \"video\", or \"webrtc\"")
		}
	case "ws":
		// WebSocket carrier. Client-side TLS to a CDN edge needs an SNI/Host, so
		// ws_tls requires ws_host; the server side (plain, behind the CDN) needs neither.
		// A rotating edge POOL carries its own per-SNI hosts (WSEdgeSNIs) instead of a
		// single WSHost, so ws_host is not required when a pool is configured.
		if c.WSTLS && c.Role == "client" && c.WSHost == "" && len(c.WSEdgeIPs) == 0 {
			return errors.New("ws_tls requires ws_host (the TLS SNI / fronting domain)")
		}
		// ECH hides the SNI, so it only makes sense on a wss client (it is carried in
		// the TLS ClientHello). Reject a config that asks for ECH without wss, and make
		// sure the supplied ECHConfigList actually decodes.
		if c.WSECH != "" {
			if !c.WSTLS || c.Role != "client" {
				return errors.New("ws_ech requires ws_tls on a client")
			}
			if _, err := base64.StdEncoding.DecodeString(c.WSECH); err != nil {
				return errors.New("ws_ech is not valid base64")
			}
		}
		// xhttp upstream style: packet-up (default) or grpc ("stream" is a legacy alias for
		// grpc). grpc is a single full-duplex request and needs HTTP/2 to the edge, so on a
		// single-edge client it requires ws_tls (a pool is always wss; the server auto-detects).
		switch c.WSXHTTPMode {
		case "", "packet", "stream", "grpc":
		default:
			return errors.New("ws_xhttp_mode must be \"packet\", \"stream\", or \"grpc\"")
		}
		if (c.WSXHTTPMode == "stream" || c.WSXHTTPMode == "grpc") && c.Role == "client" && !c.WSTLS && len(c.WSEdgeIPs) == 0 {
			return errors.New("ws_xhttp_mode \"" + c.WSXHTTPMode + "\" requires ws_tls (needs HTTP/2 to the edge)")
		}
		// Edge pool: a client+wss rotation set; every SNI's ECH must decode.
		if len(c.WSEdgeIPs) > 0 || len(c.WSEdgeSNIs) > 0 {
			if c.Role != "client" || !c.WSTLS {
				return errors.New("ws edge pool requires ws_tls on a client")
			}
			if len(c.WSEdgeIPs) == 0 || len(c.WSEdgeSNIs) == 0 {
				return errors.New("ws edge pool needs at least one edge IP and one SNI")
			}
			for _, s := range c.WSEdgeSNIs {
				if s.Host == "" {
					return errors.New("ws edge pool: an SNI entry has no host")
				}
				if s.ECH != "" {
					if _, err := base64.StdEncoding.DecodeString(s.ECH); err != nil {
						return errors.New("ws edge pool: an SNI has invalid base64 ech")
					}
				}
			}
		}
	default:
		return errors.New("transport must be \"udp\", \"tcp\", \"raw\", \"flux\", or \"ws\"")
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
	if c.Fec {
		// FEC repairs lost datagrams from parity — it only makes sense on the datagram
		// carriers (udp / raw / flux). On tcp/ws the stream is already reliable, so FEC
		// there is wasted bandwidth that fights TCP's own retransmit/congestion control.
		switch c.Transport {
		case "", "udp", "raw", "flux":
		default:
			return errors.New("fec is only supported on the datagram carriers (udp, raw, flux) — not tcp/ws")
		}
		if c.FecData < 0 || c.FecParity < 0 {
			return errors.New("fec_data / fec_parity must be >= 0 (0 defaults to 10 / 3)")
		}
		// Validate the EFFECTIVE geometry — the same defaulting applyDefaults() will do
		// AFTER validate() runs. Checking the raw values would let e.g. fec_data=254 with
		// fec_parity omitted pass (254<=255) and then become 254+3=257, which the codec
		// rejects (newFECCodec needs n+k<=256) so newFecPair silently disables FEC even
		// though the user asked for it. An out-of-range request must be a clean config
		// error here, not a silent FEC-off at runtime.
		ed, ep := c.FecData, c.FecParity
		if ed == 0 {
			ed = 10
		}
		if ep == 0 {
			ep = 3
		}
		if ed < 1 || ep < 1 || ed+ep > 255 {
			return errors.New("effective fec_data (default 10) + fec_parity (default 3) must satisfy fec_data>=1, fec_parity>=1, fec_data+fec_parity<=255")
		}
	}
	if c.Cover && c.Transport != "tcp" {
		return errors.New("cover (TLS) requires transport \"tcp\"")
	}
	if c.Cover && c.CoverSNI == "" {
		return errors.New("cover (TLS) requires cover_sni (the SNI to present)")
	}
	return nil
}
