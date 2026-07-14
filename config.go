package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
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

	// Transport selects the carrier for core frames: "udp" (default,
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
	// so per-source/stateful egress filters can't pin the real IP. RealPeer (server)
	// is the client's REAL IP: with a forged source the server cannot learn where to
	// reply, so it is told here (the AEAD still authenticates every frame). Raw + bip +
	// crypto only; needs CAP_NET_RAW. Both empty = no spoofing.
	SpoofSrc string `json:"spoof_src_ip"`
	RealPeer string `json:"real_peer_ip"`

	// SpoofDst forges the outer IPv4 DESTINATION to a decoy IP (e.g. a reachable,
	// unfiltered host) so an on-path censor sees traffic to the decoy, not to the real
	// server. Both ends carry the same decoy: the client puts it in the header dst while
	// still routing to the real server; the server therefore cannot receive on an ordinary
	// AF_INET raw socket (the kernel drops packets whose dst isn't local) and instead reads
	// with AF_PACKET, and replies with the decoy as the source. A server using SpoofDst
	// must also set RealPeer (the forged source hides the client's real IP). Raw + bip +
	// crypto only; needs CAP_NET_RAW. Empty = no destination spoofing.
	SpoofDst string `json:"spoof_dst_ip"`

	Listen string `json:"listen"` // server: bind address, e.g. "0.0.0.0:9000"
	// ListenIPs is the server-side rotation-pool bind list: one "ip:port" per SELECTED pool IP. When set
	// (a pooled udp/tcp server), the server binds each of these instead of the single Listen/0.0.0.0, so
	// only the pool IPs listen and each reply leaves from the IP the client dialed. Empty = use Listen.
	ListenIPs []string `json:"listen_ips"`
	Peer      string   `json:"peer"` // client: server address, e.g. "1.2.3.4:9000"
	// PeerIPs is a rotation pool of DESTINATION endpoints for the direct transports (tcp/udp/raw/
	// flux): the client cycles them and burns a blocked one, so a single blocked server IP doesn't
	// kill the tunnel (the direct-transport analogue of the ws edge pool). When it has >1 entry it
	// overrides the single Peer; each entry is "ip:port" for udp/tcp or "ip" for raw/flux (the port
	// is ignored there). PeerRotateSecs is the proactive rotation interval (0 = rotate only on a
	// dead peer); PeerAutoBurn drops a peer whose handshake never completes (the burn signal is a
	// stalled handshake, so on a crypto-off udp pool — which has no handshake — only PeerRotateSecs
	// applies and auto-burn is inert; raw/flux/tcp always have a liveness signal). PeerStatusPath is
	// the status file the node exposes to the panel (which endpoint is active / burned).
	PeerIPs        []string `json:"peer_ips"`
	PeerRotateSecs int      `json:"peer_rotate_secs"`
	PeerAutoBurn   bool     `json:"peer_auto_burn"`
	PeerStatusPath string   `json:"peer_status_path"`
	// SrcIPs is the SOURCE rotation pool: the client's OWN IPs that it sends FROM, cycled alongside
	// PeerIPs (same PeerRotateSecs / PeerAutoBurn) so a blocked source IP is walked off too. Each is a
	// bare IPv4 (this node's own address). Client + direct transports only; on raw it is ignored under
	// spoof_src (a forged source is a deliberate decoy). raw/flux stamp the source per packet; udp
	// rebinds its socket; tcp re-dials with a new LocalAddr. When set it supersedes the single BindIP.
	SrcIPs []string `json:"src_ips"`
	// SrcStatusPath is the status file the SOURCE pool writes (its own live state + the pin cmd file),
	// separate from PeerStatusPath so the panel can show and drive both the source and destination pools.
	// Empty = the source pool has no panel-facing status / manual pin (it still rotates and self-heals).
	SrcStatusPath string `json:"src_status_path"`
	// PeerSrcIPs (SERVER, raw/flux only) is the client's SOURCE pool — the set of IPs the client may send
	// FROM once its source rotates. raw/flux servers see every host on the wire and pre-filter incoming
	// frames by the learned peer source; without this the server would drop a rotated client source before
	// crypto and never re-bind to it (stranding the tunnel until a rebuild). Listing the client's known
	// sources lets a rotated-but-expected source reach crypto (which authenticates it) while still dropping
	// unrelated hosts pre-crypto. Empty = strict single-source filter (non-pool tunnels). udp/tcp bind a
	// socket per source and re-learn naturally, so they don't need this.
	PeerSrcIPs []string `json:"peer_src_ips"`
	// BindIP is the source IP the client dials FROM (its own node IP). On a host with
	// several IPs the kernel would otherwise egress from the primary IP; binding pins the
	// outbound socket to this node's registered IP so the peer/CDN sees the expected source.
	// Empty = let the kernel choose. TCP-family carriers only (tcp/ws/xhttp).
	BindIP string `json:"bind_ip"`

	TunName string `json:"tun_name"` // requested interface name, e.g. "tnl0"
	TunAddr string `json:"tun_addr"` // local L3 address with prefix, e.g. "10.200.0.1/24"
	MTU     int    `json:"mtu"`      // TUN MTU, e.g. 1400

	Keepalive int `json:"keepalive"` // client ping interval in seconds (default 15)
	// DeadAfterSecs (client) is the per-tunnel self-heal deadline: the carrier is declared dead — and the
	// client re-establishes / fails over — if no authenticated inbound frame arrives within this many
	// seconds. It sets the read-deadline ceiling (b.idle for tcp/ws/xhttp; the stale window for udp/raw/
	// flux), so an operator can make a tunnel heal faster than the default (~3×keepalive ping-loss, 60s
	// idle backstop). 0 = use the default formula. Clamped to >=2×keepalive so a healthy pinging link is
	// never mis-reaped, so for a very short window lower Keepalive too.
	DeadAfterSecs int       `json:"dead_after_secs"`
	Crypto        CryptoCfg `json:"crypto"`

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
	// the cover the server borrows. TCP only; core/PSK runs inside the TLS tunnel.
	Cover    bool   `json:"cover"`
	CoverSNI string `json:"cover_sni"`

	// WebSocket carrier (Transport=="ws"): the core stream rides RFC 6455 binary
	// frames after an HTTP Upgrade, so it can be fronted through a CDN. WSHost is the
	// Host header (and TLS SNI) — the fronting/origin domain; WSPath the request path
	// ("/" default); WSTLS makes the client speak wss:// (standard TLS to the CDN edge)
	// before the upgrade. The server stays plain (the CDN terminates TLS and forwards
	// the WebSocket to the origin). TCP-family; obfs/crypto apply as with tcp.
	WSHost string `json:"ws_host"`
	WSPath string `json:"ws_path"`
	WSTLS  bool   `json:"ws_tls"`
	// SNISplit fragments the wss ClientHello across two TCP segments so the cleartext SNI lands on
	// the segment boundary — a stateless SNI-blocklist DPI can no longer match the full hostname
	// (SNI fragmentation). A cheap complement to ECH for edges/censors where ECH is unavailable;
	// ws/xhttp client + wss only. SplitPos is the split offset into the ClientHello (0 = auto: the
	// middle of the cleartext hostname; naturally a no-op under ECH, where the SNI is encrypted).
	SNISplit bool `json:"sni_split"`
	SplitPos int  `json:"split_pos"`
	// SNIMode picks how the split is sent: "split" (default) = two in-order segments; "disorder"
	// additionally sends the head segment at a low TTL (SplitTTL) so it expires in transit and a
	// reassembling DPI sees the ClientHello out of order, while the kernel retransmits it so the
	// server still gets the real bytes. SplitTTL is the disorder head TTL (0 = default).
	SNIMode  string `json:"sni_mode"`
	SplitTTL int    `json:"split_ttl"`
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

	// StatusPath is the general per-core status file for the connectionless datagram transports
	// (udp/raw/flux): the client writes its precise self-heal event ring here so the node/panel
	// system log can surface disconnects/recoveries with a core-observed reason. Empty = off. The
	// ws pool uses WSStatusPath instead; keeping the two separate lets the node tell a pool core
	// (which has SIGHUP/SIGUSR handlers) apart from a plain datagram core (which does not).
	StatusPath string `json:"status_path"`

	// WSWarmStandby keeps a SECOND, fully-handshaked carrier connection to another pool edge
	// warm in the background (make-before-break). On the active carrier's failure or a proactive
	// rotation the standby is promoted instantly instead of dialing fresh, so the TUN never sees a
	// gap. Client + ws edge pool only (ignored otherwise); default false. The server side (no
	// connect-time eviction + downstream-follows-data) is always on and single-connection-safe.
	WSWarmStandby bool `json:"ws_warm_standby"`

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

	// FakeDesync (client, raw/flux carriers only) emits FakeCount decoy packets to the peer
	// just before each handshake to mis-sync a stateful DPI. A low-TTL decoy expires a few
	// hops out (before the server); a bad-checksum decoy is dropped by the server's IP stack —
	// either way an on-path DPI ingests the decoy and mis-tracks the flow while the real,
	// AEAD-authenticated session is untouched. It only helps where the core builds the whole
	// IPv4 header (raw/flux); the kernel-socket carriers (udp/tcp/ws) cannot forge a
	// TTL/checksum. Needs CAP_NET_RAW (the raw/flux carriers already require it).
	FakeDesync bool   `json:"fake_desync"`
	FakeTTL    int    `json:"fake_ttl"`   // low-TTL decoy hop budget (default 4)
	FakeCount  int    `json:"fake_count"` // decoys per handshake (default 2)
	FakeMode   string `json:"fake_mode"`  // "ttl" (default) | "badsum" | "both"

	// GSO opens the TUN with a virtio-net header and TCP/UDP segmentation
	// offload, so the kernel hands the core large super-packets on bulk
	// transfers instead of many MTU-sized ones — fewer syscalls/copies, higher
	// throughput. It is a local optimization only (the wire format is unchanged)
	// and each side can enable it independently. Linux only.
	GSO bool `json:"gso"`

	// Tuning carries the operator-tunable operational timing knobs (pool health FSM, dead-detection
	// windows, rotation default). Optional: any zero/empty field leaves the compiled-in default. The
	// packet layer applies these once at startup (packet.ApplyTuning) — safe because one core process
	// serves one tunnel. nil = all defaults.
	Tuning *TuningCfg `json:"tuning"`
}

// TuningCfg is the JSON shape of the config's `tuning` object. Every field is optional (zero/empty =
// keep default); the packet layer clamps each to a sane range before applying it.
type TuningCfg struct {
	SuspectBackoff      []int64 `json:"suspect_backoff"`          // retest schedule (secs) for a suspect pool entry
	DeadRetestSecs      int64   `json:"dead_retest_secs"`         // slow retest interval (secs) for a dead entry
	PinTTLSecs          int64   `json:"pin_ttl_secs"`             // manual-pin force window (dead-pin release cap)
	DataFailThreshold   int     `json:"data_fail_threshold"`      // short sessions in a row before suspecting an IP
	DataGoodWindowSecs  int64   `json:"data_good_window_secs"`    // recency window for the outage guard
	IdleMult            int64   `json:"idle_mult"`                // ws/tcp read deadline = mult × keepalive
	IdleMinSecs         int64   `json:"idle_min_secs"`            // …floored at this many seconds
	SessionStaleMult    int64   `json:"session_stale_mult"`       // udp/raw/flux stale window = mult × keepalive
	SessionStaleMinSecs int64   `json:"session_stale_min_secs"`   // …floored at this many seconds
	PingLossThreshold   int     `json:"ping_loss_threshold"`      // unanswered keepalives before a client closes
	MinLivenessSecs     int64   `json:"min_liveness_secs"`        // shortest session that still counts as healthy
	ProbeTimeoutSecs    int64   `json:"probe_timeout_secs"`       // per-edge reachability probe timeout
	FluxRotateDefSecs   int64   `json:"flux_rotate_default_secs"` // flux epoch length when unset per-tunnel
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
	if c.MTU <= 0 { // <=0 (not just ==0): a negative MTU would reach `ip link set … mtu N` and fail
		c.MTU = 1400
	}
	if c.Keepalive <= 0 { // <=0: a negative keepalive makes jitter() fire immediately -> ping busy-loop
		c.Keepalive = 15
	}
	if c.Crypto.Cipher == "" {
		c.Crypto.Cipher = "aes-256-gcm"
	}
	if c.Transport == "" {
		c.Transport = "udp"
	}
	// A destination rotation pool OWNS the dial target: seed the single Peer from the pool's first
	// entry so the initial datagram dial (cfg.Peer) and the pool's starting endpoint (cur=0) always
	// agree — otherwise a fail() at cur=0 would burn the wrong entry and the mismatched Peer would be
	// dropped on the first rotation. The pool is authoritative, so this overrides any Peer the caller
	// also set. A bare-IP first entry is fine for raw/flux (they ignore the port) and "ip:port" for
	// udp/tcp; both were validated. It also satisfies the client-role "peer" check for a pool-only cfg.
	if len(c.PeerIPs) > 0 {
		c.Peer = c.PeerIPs[0]
	}
	if c.Transport == "raw" && c.RawProfile == "" {
		c.RawProfile = "bip"
	}
	if c.Transport == "flux" {
		if c.FluxRotateSecs == 0 {
			// Honor the tuned global default (flux_rotate_default_secs) when the tunnel leaves the epoch
			// length unset; fall back to 600 when the knob is unset/invalid. Resolving it to a concrete
			// value HERE (not leaving 0 for the carrier's defaultFluxRotate) keeps both ends computing the
			// same epoch and avoids a divide-by-zero in fluxEpochAt. Both ends share the global tuning.
			d := int64(600)
			if c.Tuning != nil && c.Tuning.FluxRotateDefSecs > 0 {
				if d = c.Tuning.FluxRotateDefSecs; d > 86400 {
					d = 86400
				}
			}
			c.FluxRotateSecs = int(d)
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
	if c.FakeDesync { // fake-packet desync defaults (raw/flux client)
		if c.FakeTTL <= 0 {
			c.FakeTTL = 4
		}
		if c.FakeCount <= 0 {
			c.FakeCount = 2
		}
		if c.FakeMode == "" {
			c.FakeMode = "ttl"
		}
	}
}

// rawProfiles is the set of valid raw-transport encapsulation profiles. It
// mirrors the map in the packet package (kept here so config validation does not
// depend on that package).
var rawProfiles = map[string]bool{
	"bip": true, "ipip": true, "gre": true, "icmp": true, "udp": true, "tcp": true,
}

// validatePoolEndpoint checks one rotation-pool entry (field names it for the error). The pool swaps
// the endpoint with no DNS step, so every entry must be a literal IP. With needPort (the udp/tcp
// DESTINATION) it is "ip:port" — the host must be an IP and the port valid; otherwise (raw/flux
// destinations, and every SOURCE IP) it is a bare IPv4 — an accidental ":port" is tolerated/dropped.
func validatePoolEndpoint(field, e string, needPort bool) error {
	if needPort {
		host, port, err := net.SplitHostPort(e)
		if err != nil {
			return errors.New(field + " entry " + strconv.Quote(e) + " must be \"ip:port\"")
		}
		if net.ParseIP(host) == nil {
			return errors.New(field + " entry " + strconv.Quote(e) + " has a non-IP host (the pool dials IPs directly, no DNS)")
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return errors.New(field + " entry " + strconv.Quote(e) + " has an invalid port")
		}
		return nil
	}
	host := e
	if h, _, err := net.SplitHostPort(e); err == nil { // tolerate an accidental ip:port
		host = h
	}
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		return errors.New(field + " entry " + strconv.Quote(e) + " must be an IPv4 address")
	}
	return nil
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
		for _, la := range c.ListenIPs { // pooled server: each bind must be a valid IP:port (we bind these directly)
			host, port, err := net.SplitHostPort(la)
			if err != nil {
				return fmt.Errorf("listen_ips entry %q must be host:port: %w", la, err)
			}
			if net.ParseIP(host) == nil {
				return fmt.Errorf("listen_ips entry %q has a non-IP host (each bind must be a literal IP)", la)
			}
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("listen_ips entry %q has an invalid port", la)
			}
		}
	case "client":
		if c.Peer == "" && len(c.PeerIPs) == 0 {
			return errors.New("client role requires \"peer\" (or a peer_ips rotation pool)")
		}
	default:
		return errors.New("role must be \"server\" or \"client\"")
	}
	if c.BindIP != "" && net.ParseIP(c.BindIP) == nil {
		return errors.New("bind_ip must be a valid IP address")
	}
	if c.DeadAfterSecs != 0 && (c.DeadAfterSecs < 10 || c.DeadAfterSecs > 300) {
		return errors.New("dead_after_secs must be 0 (default) or between 10 and 300")
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
		if (c.SpoofSrc != "" || c.RealPeer != "" || c.SpoofDst != "") && c.RawProfile != "" && c.RawProfile != "bip" {
			return errors.New("IP spoofing is only supported on the raw \"bip\" profile for now")
		}
		if c.SpoofSrc != "" && net.ParseIP(c.SpoofSrc).To4() == nil {
			return errors.New("spoof_src_ip must be an IPv4 address")
		}
		if c.RealPeer != "" && net.ParseIP(c.RealPeer).To4() == nil {
			return errors.New("real_peer_ip must be an IPv4 address")
		}
		if c.SpoofDst != "" && net.ParseIP(c.SpoofDst).To4() == nil {
			return errors.New("spoof_dst_ip must be an IPv4 address")
		}
		// A server that expects decoy-destination packets receives them via AF_PACKET and
		// replies with the decoy as source, so it can never learn the client's real address
		// from the wire — RealPeer must supply it.
		if c.SpoofDst != "" && c.Role == "server" && c.RealPeer == "" {
			return errors.New("spoof_dst_ip on a server requires real_peer_ip (the client's real IP to reply to)")
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
		// SNI fragmentation splits the wss ClientHello, so it needs wss on a client. split_pos is a
		// byte offset into the ClientHello (0 = auto: middle of the hostname); cap it so a runaway
		// value can't push the split past a plausible ClientHello.
		if c.SNISplit {
			if !c.WSTLS || c.Role != "client" {
				return errors.New("sni_split requires ws_tls on a client")
			}
			if c.SplitPos < 0 || c.SplitPos > 1400 {
				return errors.New("split_pos must be between 0 and 1400")
			}
			switch c.SNIMode {
			case "", "split", "disorder", "fake":
			default:
				return errors.New("sni_mode must be \"split\", \"disorder\", or \"fake\"")
			}
			if c.SplitTTL < 0 || c.SplitTTL > 255 {
				return errors.New("split_ttl must be between 0 and 255")
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
			// Every edge is dialed directly as "ip:port" with no DNS step, exactly like the other
			// rotation pools — so validate the literal IP+port here instead of letting a malformed/
			// hostname entry reach the data plane and silently burn the edge.
			for _, e := range c.WSEdgeIPs {
				if err := validatePoolEndpoint("ws_edge_ips", e, true); err != nil {
					return err
				}
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
	// PeerIPs is the DESTINATION rotation pool for the direct transports. It is a client-side
	// dial-layer feature: a server listens (it does not dial), and ws has its own edge pool, so
	// the pool is meaningless there. Each entry must be a literal IP the pool can swap to with no
	// DNS step — "ip:port" for the stream/datagram carriers (udp/tcp), a bare IPv4 for raw/flux
	// (which address the peer by IP; any port is ignored). The single Peer is still allowed
	// alongside it (applyDefaults seeds Peer from the first pool entry when only the pool is set).
	if len(c.PeerIPs) > 0 {
		if c.Role != "client" {
			return errors.New("peer_ips is a client rotation pool (a server listens, it does not dial)")
		}
		switch c.Transport {
		case "", "udp", "tcp", "raw", "flux":
		default:
			return errors.New("peer_ips is only for the direct transports (udp, tcp, raw, flux) — ws has its own edge pool")
		}
		// udp/tcp dial "ip:port"; raw/flux address a bare IPv4 (parseIP4 rejects v6 and a hostname).
		needPort := c.Transport != "raw" && c.Transport != "flux"
		for _, e := range c.PeerIPs {
			if err := validatePoolEndpoint("peer_ips", e, needPort); err != nil {
				return err
			}
		}
	}
	// SrcIPs is the client-side SOURCE rotation pool (the node's own IPs). Same scoping as PeerIPs, but
	// every entry is a bare IPv4 regardless of carrier (a source is never "ip:port").
	if len(c.SrcIPs) > 0 {
		if c.Role != "client" {
			return errors.New("src_ips is a client source rotation pool (a server does not dial)")
		}
		switch c.Transport {
		case "", "udp", "tcp", "raw", "flux":
		default:
			return errors.New("src_ips is only for the direct transports (udp, tcp, raw, flux) — ws has its own edge pool")
		}
		for _, e := range c.SrcIPs {
			if err := validatePoolEndpoint("src_ips", e, false); err != nil {
				return err
			}
		}
	}
	if len(c.PeerSrcIPs) > 0 {
		// peer_src_ips is the SERVER's copy of the client's source pool (raw/flux only). Validate it like
		// src_ips so a typo fails the config load loudly instead of being silently dropped in
		// SetPeerSources — a dropped source would re-strand the tunnel on the client's next rotation.
		if c.Role != "server" {
			return errors.New("peer_src_ips is a server-side view of the client's source pool")
		}
		switch c.Transport {
		case "raw", "flux":
		default:
			return errors.New("peer_src_ips is only for the raw/flux transports (udp/tcp re-learn the source on their own)")
		}
		for _, e := range c.PeerSrcIPs {
			if err := validatePoolEndpoint("peer_src_ips", e, false); err != nil {
				return err
			}
		}
	}
	if c.PeerRotateSecs < 0 {
		return errors.New("peer_rotate_secs must be >= 0 (0 = rotate only on a dead peer)")
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
	if c.FakeDesync {
		// Desync is delivered two ways: raw/flux build the whole IPv4 header, so they forge decoy
		// packets directly; tcp/ws own a kernel TCP connection, so they INJECT decoy TCP segments
		// on its 4-tuple via AF_PACKET (see tcp_inject_linux.go). Plain udp has no such hook. It is
		// a client-side mechanism; a server that carries the same fields simply ignores them.
		switch c.Transport {
		case "raw", "flux", "tcp", "ws":
		default:
			return errors.New("fake_desync is supported on the raw, flux, tcp and ws carriers (not plain udp)")
		}
		if c.FakeTTL < 0 || c.FakeTTL > 255 {
			return errors.New("fake_ttl must be between 0 and 255 (0 defaults to 4)")
		}
		if c.FakeCount < 0 || c.FakeCount > 64 {
			return errors.New("fake_count must be between 0 and 64 (0 defaults to 2)")
		}
		switch c.FakeMode {
		case "", "ttl", "badsum", "both":
		default:
			return errors.New("fake_mode must be \"ttl\", \"badsum\", or \"both\"")
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
