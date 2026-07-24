// Command tnl-core is the custom data-plane core for the tunnel fleet
// manager. It carries raw L3 packets over a TUN device across a selectable
// transport (udp/tcp/raw/flux/ws/xhttp) with optional configurable crypto.
//
// Usage:
//
//	tnl-core --config /run/tnl/core-<id>.json
//
// The node agent owns the config file; the core just runs what it is told.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// version is stamped into logs so the panel can tell which core a node runs.
const version = "0.1.0-core"

func main() {
	cfgPath := flag.String("config", "", "path to core JSON config")
	showVer := flag.Bool("version", false, "print version and exit")
	probeSpoof := flag.Bool("probe-spoof", false, "print IP-spoofing capability (JSON) and exit")
	flag.Parse()

	if *showVer {
		os.Stdout.WriteString(version + "\n")
		return
	}
	if *probeSpoof {
		b, _ := json.Marshal(packet.ProbeSpoof())
		os.Stdout.Write(append(b, '\n'))
		return
	}
	if *cfgPath == "" {
		log.Fatal("tnl-core: --config is required")
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("tnl-core: config: %v", err)
	}

	// Apply any operator-tuned operational timing BEFORE building carriers/pools (they read these
	// package vars at construction). One process = one tunnel, so this is safe process-global state.
	if t := cfg.Tuning; t != nil {
		packet.ApplyTuning(packet.TuningInput{
			SuspectBackoff: t.SuspectBackoff, DeadRetestSecs: t.DeadRetestSecs, PinTTLSecs: t.PinTTLSecs,
			DataFailThreshold: t.DataFailThreshold, DataGoodWindowSecs: t.DataGoodWindowSecs,
			IdleMult: t.IdleMult, IdleMinSecs: t.IdleMinSecs,
			SessionStaleMult: t.SessionStaleMult, SessionStaleMinSecs: t.SessionStaleMinSecs,
			PingLossThreshold: t.PingLossThreshold, MinLivenessSecs: t.MinLivenessSecs,
			ProbeTimeoutSecs: t.ProbeTimeoutSecs,
		})
	}
	// Pin the datagram-carrier socket buffers (udp/raw/flux) BEFORE any socket is opened. cfg.SockBuf is
	// resolved by applyDefaults (4 MiB default; negative = leave the kernel default).
	packet.SetSockBuf(cfg.SockBuf)

	// Open the TUN device BEFORE building the sealer. The sealer's constructor may
	// draw from crypto/rand; on hosts without getrandom(2) that opens /dev/urandom
	// and registers it with the runtime netpoller, which can leave a subsequently
	// opened TUN fd in a half-pollable state (reads fail with "not pollable" and
	// the reader loop dies). Setting up the TUN first avoids that ordering hazard.
	dev, err := tun.Open(cfg.TunName, cfg.MTU, cfg.TunAddr, cfg.GSO)
	if err != nil {
		log.Fatalf("tnl-core: tun: %v", err)
	}
	defer dev.Close()

	cipherName := "off"
	if cfg.Crypto.Enabled {
		// Validate the cipher/PSK up front (fail fast); the carriers build the
		// actual per-session sealers after the ephemeral handshake.
		s, err := crypto.NewSealer(cfg.Crypto.Cipher, cfg.Crypto.PSK, cfg.Role == "client")
		if err != nil {
			log.Fatalf("tnl-core: crypto: %v", err)
		}
		cipherName = s.Name
	} else {
		if cfg.Obfs {
			log.Fatalf("tnl-core: obfs requires crypto (there is no key to obfuscate with) — enable crypto or disable obfs")
		}
		// Clear mode has NO authentication: a single spoofed datagram can rebind
		// the peer or inject a packet into the TUN. Make that impossible to miss.
		log.Printf("tnl-core: WARNING crypto is DISABLED — the tunnel is unauthenticated " +
			"and unencrypted; anyone who can send a packet to this listener can hijack or " +
			"inject into it. Enable crypto unless this is a trusted, isolated link.")
	}
	gsoTag := ""
	if cfg.GSO {
		gsoTag = " gso"
	}
	log.Printf("tnl-core %s: tun=%s addr=%s mtu=%d cipher=%s role=%s%s",
		version, dev.Name, cfg.TunAddr, cfg.MTU, cipherName, cfg.Role, gsoTag)

	// carrier is satisfied by all four core implementations — UDP (packet.UDP),
	// TCP-family (packet.TCP), raw (packet.Raw) and flux (packet.Flux);
	// cfg.Transport selects which one is built.
	type carrier interface {
		Run() error
		Close() error
	}
	var b carrier
	ka := time.Duration(cfg.Keepalive) * time.Second
	obfsTag := ""
	if cfg.Obfs {
		obfsTag = " obfs"
	}
	fecTag := ""
	if cfg.Fec {
		fecTag = fmt.Sprintf(" fec=%d+%d", cfg.FecData, cfg.FecParity)
	}
	cryptoOn := cfg.Crypto.Enabled
	switch cfg.Transport {
	case "tcp":
		switch cfg.Role {
		case "server":
			la := cfg.ListenIPs // pooled server: bind each selected pool IP; else the single Listen addr
			if len(la) == 0 {
				la = []string{cfg.Listen}
			}
			b, err = packet.ListenTCP(la, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-core: listening (core/tcp%s%s) on %v", obfsTag, coverTag(cfg.Cover), la)
			}
		case "client":
			b, err = packet.DialTCP(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-core: dialing (core/tcp%s%s) %s", obfsTag, coverTag(cfg.Cover), cfg.Peer)
			}
		}
	case "raw":
		switch cfg.Role {
		case "server":
			b, err = packet.ListenRaw(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.RealPeer, cfg.SpoofDst, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: listening (core/raw:%s%s%s) on %s", cfg.RawProfile, obfsTag, fecTag, cfg.Listen)
			}
		case "client":
			b, err = packet.DialRaw(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.RawProfile, cfg.SpoofSrc, cfg.SpoofDst, cfg.Fec, cfg.FecData, cfg.FecParity, cfg.RawProto)
			if err == nil {
				log.Printf("tnl-core: dialing (core/raw:%s%s%s) %s", cfg.RawProfile, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "flux":
		rotate := time.Duration(cfg.FluxRotateSecs) * time.Second
		switch cfg.Role {
		case "server":
			b, err = packet.ListenFlux(cfg.Listen, dev, ka, rotate, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.FluxCarrier, cfg.FluxShape, cfg.FluxEpochOffset, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: listening (core/flux:%s/%s rotate=%ds%s%s)", cfg.FluxCarrier, cfg.FluxShape, cfg.FluxRotateSecs, obfsTag, fecTag)
			}
		case "client":
			b, err = packet.DialFlux(cfg.Peer, dev, ka, rotate, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.FluxCarrier, cfg.FluxShape, cfg.FluxEpochOffset, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: dialing (core/flux:%s/%s rotate=%ds%s%s) %s", cfg.FluxCarrier, cfg.FluxShape, cfg.FluxRotateSecs, obfsTag, fecTag, cfg.Peer)
			}
		}
	case "ws":
		switch cfg.Role {
		case "server":
			if cfg.WSXHTTP {
				b, err = packet.ListenXHTTP(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher)
				if err == nil {
					log.Printf("tnl-core: listening (core/xhttp%s) on %s", obfsTag, cfg.Listen)
				}
				break
			}
			b, err = packet.ListenWS(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher)
			if err == nil {
				log.Printf("tnl-core: listening (core/ws%s) on %s", obfsTag, cfg.Listen)
			}
		case "client":
			carrier := "ws"
			if cfg.WSXHTTP {
				carrier = "xhttp"
			}
			if len(cfg.WSEdgeIPs) > 0 { // rotating edge pool overrides the single edge (ws or xhttp)
				snis := make([]packet.WSPoolSNI, len(cfg.WSEdgeSNIs))
				for i, s := range cfg.WSEdgeSNIs {
					snis[i] = packet.WSPoolSNI{Host: s.Host, ECH: s.ECH, Path: s.Path}
				}
				b, err = packet.DialWSPoolCfg(dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher,
					cfg.WSEdgeIPs, snis, time.Duration(cfg.WSRotateSecs)*time.Second, cfg.WSAutoBurn, cfg.WSStatusPath, cfg.WSXHTTP, cfg.WSXHTTPMode, cfg.WSWarmStandby)
				if err == nil {
					warmTag := ""
					if cfg.WSWarmStandby {
						warmTag = " warm-standby"
					}
					log.Printf("tnl-core: dialing (core/%s%s wss ech pool: %dIP×%dSNI rotate=%ds auto_burn=%v%s)",
						carrier, obfsTag, len(cfg.WSEdgeIPs), len(cfg.WSEdgeSNIs), cfg.WSRotateSecs, cfg.WSAutoBurn, warmTag)
				}
				break
			}
			var echList []byte
			if cfg.WSECH != "" { // validated as base64 in Config.Validate
				echList, _ = base64.StdEncoding.DecodeString(cfg.WSECH)
			}
			if cfg.WSXHTTP { // single-edge xhttp carrier
				b, err = packet.DialXHTTP(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList, cfg.WSXHTTPMode)
				if err == nil {
					mode := cfg.WSXHTTPMode
					if mode == "" {
						mode = "packet"
					}
					log.Printf("tnl-core: dialing (core/xhttp:%s%s wss) %s", mode, obfsTag, cfg.Peer)
				}
				break
			}
			b, err = packet.DialWS(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.WSHost, cfg.WSPath, cfg.WSTLS, echList)
			if err == nil {
				tlsTag := ""
				if cfg.WSTLS {
					tlsTag = " wss"
				}
				if len(echList) > 0 {
					tlsTag += " ech"
				}
				log.Printf("tnl-core: dialing (core/ws%s%s) %s", obfsTag, tlsTag, cfg.Peer)
			}
		}
	case "dns":
		switch cfg.Role {
		case "server":
			b, err = packet.ListenDNS(dev, cfg.Listen, cfg.DNSZone, cfg.Crypto.PSK, cfg.Crypto.Cipher)
			if err == nil {
				log.Printf("tnl-core: listening (core/dns zone=%s) on %s", cfg.DNSZone, cfg.Listen)
			}
		case "client":
			b, err = packet.DialDNS(dev, cfg.DNSResolvers, cfg.DNSZone, cfg.Crypto.PSK, cfg.Crypto.Cipher, ka)
			if err == nil {
				log.Printf("tnl-core: dialing (core/dns zone=%s via resolvers %s)", cfg.DNSZone, strings.Join(cfg.DNSResolvers, ", "))
			}
		}
	default: // "udp"
		switch cfg.Role {
		case "server":
			la := cfg.ListenIPs // pooled server: bind each selected pool IP; else the single Listen addr
			if len(la) == 0 {
				la = []string{cfg.Listen}
			}
			b, err = packet.Listen(la, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: listening (core/udp%s%s) on %v", obfsTag, fecTag, la)
			}
		case "client":
			b, err = packet.Dial(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Fec, cfg.FecData, cfg.FecParity)
			if err == nil {
				log.Printf("tnl-core: dialing (core/udp%s%s) %s", obfsTag, fecTag, cfg.Peer)
			}
		}
	}
	if err != nil {
		log.Fatalf("tnl-core: transport: %v", err)
	}
	// Pin the client's outbound source IP to this node's own registered IP when set, so on a
	// multi-IP host the peer/CDN sees that IP instead of the kernel's default primary. Only the
	// TCP-family carriers (tcp/ws/xhttp) implement it; others ignore it.
	if cfg.Role == "client" && cfg.BindIP != "" {
		if s, ok := b.(interface{ SetSourceIP(string) }); ok {
			s.SetSourceIP(cfg.BindIP)
			log.Printf("tnl-core: binding outbound source IP to %s", cfg.BindIP)
		}
	}
	// Per-tunnel self-heal deadline (client): when set, tighten the carrier's dead-detection window so
	// this tunnel re-establishes/fails over faster than the default (~3×keepalive / 60s idle backstop).
	// Every carrier implements it; a 0 value leaves the default formula in place.
	if cfg.Role == "client" && cfg.DeadAfterSecs > 0 {
		if s, ok := b.(interface{ SetDeadAfter(int) }); ok {
			s.SetDeadAfter(cfg.DeadAfterSecs)
			// Log the EFFECTIVE deadline: the carrier clamps dead_after_secs up to >=2×keepalive
			// (deadWindow), so logging cfg.DeadAfterSecs verbatim would misreport a clamped value.
			effDead := cfg.DeadAfterSecs
			if floor := 2 * cfg.Keepalive; effDead < floor {
				effDead = floor
			}
			log.Printf("tnl-core: self-heal deadline set to %ds (>=2×keepalive)", effDead)
		}
	}
	// Datagram transports (udp/raw/flux): wire a status-file event ring so the client's precise
	// self-heal events reach the node/panel system log. Only the client writes it; the transports
	// that don't implement it (tcp/ws) simply ignore this.
	if cfg.Role == "client" && cfg.StatusPath != "" {
		if s, ok := b.(interface{ SetStatusPath(string) }); ok {
			s.SetStatusPath(cfg.StatusPath)
			log.Printf("tnl-core: writing status/events to %s", cfg.StatusPath)
		}
	}
	// Fake-packet desync (client, raw/flux): emit decoy packets before each handshake to
	// mis-sync a stateful DPI. Only the raw/flux carriers implement it (they build the IPv4
	// header themselves); the kernel-socket carriers ignore this.
	if cfg.Role == "client" && cfg.FakeDesync {
		if s, ok := b.(interface {
			SetDesync(bool, int, int, string)
		}); ok {
			s.SetDesync(true, cfg.FakeTTL, cfg.FakeCount, cfg.FakeMode)
			log.Printf("tnl-core: fake-desync on (%d decoys, ttl=%d, mode=%s)", cfg.FakeCount, cfg.FakeTTL, cfg.FakeMode)
		}
	}
	// SNI fragmentation (client, ws/xhttp): split the wss ClientHello so the cleartext SNI crosses a
	// TCP segment boundary. Only the ws/xhttp carrier implements it; others ignore this.
	if cfg.Role == "client" && cfg.SNISplit {
		if s, ok := b.(interface {
			SetSNISplit(bool, int, string, int)
		}); ok {
			mode := cfg.SNIMode
			if mode == "" {
				mode = "split"
			}
			s.SetSNISplit(true, cfg.SplitPos, mode, cfg.SplitTTL)
			log.Printf("tnl-core: SNI fragmentation on (mode=%s split_pos=%d ttl=%d)", mode, cfg.SplitPos, cfg.SplitTTL)
		}
	}
	// Destination rotation pool (client, direct transports udp/tcp/raw/flux): cycle the peer IPs and
	// burn a blocked one so a single filtered server IP doesn't kill the tunnel — the direct-transport
	// analogue of the ws edge pool. Only the direct carriers implement SetPeerPool; ws (its own edge
	// pool) and the server ignore it. Needs >=2 endpoints to actually rotate (config allows fewer only
	// as the degenerate single-peer case, which never moves).
	if cfg.Role == "client" && len(cfg.PeerIPs) >= 2 {
		if s, ok := b.(interface{ SetPeerPool(*packet.PeerPool) }); ok {
			pp := packet.NewPeerPool(cfg.PeerIPs, cfg.PeerAutoBurn, time.Duration(cfg.PeerRotateSecs)*time.Second, cfg.PeerStatusPath)
			s.SetPeerPool(pp)
			log.Printf("tnl-core: destination pool: %d peers rotate=%ds auto_burn=%v", len(cfg.PeerIPs), cfg.PeerRotateSecs, cfg.PeerAutoBurn)
		}
	}
	// Source rotation pool (client, direct transports): cycle the client's OWN source IPs alongside the
	// destination pool (same rotate/auto-burn settings). raw/flux swap the crafted-header source, udp
	// rebinds its socket, tcp re-dials with a new LocalAddr. Only the direct carriers implement it. The
	// source pool doesn't own a status file (the destination pool writes the panel-facing status).
	// >=1 (not >=2): a LONE src_ip is a fixed source that supersedes bind_ip (per the field doc) — it
	// wires a 1-entry pool that seeds the source and never rotates. Without this a single src_ip was
	// silently ignored and the kernel picked the default egress IP. A >=2 pool rotates as before.
	if cfg.Role == "client" && len(cfg.SrcIPs) >= 1 {
		if s, ok := b.(interface{ SetSourcePool(*packet.PeerPool) }); ok {
			sp := packet.NewPeerPool(cfg.SrcIPs, cfg.PeerAutoBurn, time.Duration(cfg.PeerRotateSecs)*time.Second, cfg.SrcStatusPath)
			s.SetSourcePool(sp)
			log.Printf("tnl-core: source pool: %d source IPs rotate=%ds auto_burn=%v", len(cfg.SrcIPs), cfg.PeerRotateSecs, cfg.PeerAutoBurn)
		}
	}
	// Pooled server (raw/flux): the client rotates its SOURCE IP, but these carriers see every host on the
	// wire and pre-filter incoming frames by the learned peer source. Give the server the client's known
	// source pool so a rotated source still reaches crypto (which authenticates it) and learnPeer re-binds
	// — otherwise a source rotation strands the server on the stale source until a rebuild. udp/tcp bind a
	// socket per source and re-learn naturally, so they don't implement this.
	if cfg.Role == "server" && len(cfg.PeerSrcIPs) > 0 {
		if s, ok := b.(interface{ SetPeerSources([]string) }); ok {
			s.SetPeerSources(cfg.PeerSrcIPs)
			log.Printf("tnl-core: pooled server follows client source rotation across %d source IPs", len(cfg.PeerSrcIPs))
		}
	}
	defer b.Close()

	// Clean shutdown removes the TUN (via defers) on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("tnl-core: shutting down")
		b.Close()
		dev.Close()
		os.Exit(0)
	}()

	// Live "rotate now" for a ws edge pool, driven by the node via `systemctl kill`:
	// SIGUSR1 rotates the edge IP, SIGUSR2 rotates the SNI — one dimension, no rebuild,
	// the TUN stays up while the carrier re-dials on the new edge.
	if r, ok := b.(interface {
		RotateIP()
		RotateSNI()
		ProbeAllNow()
	}); ok {
		rsig := make(chan os.Signal, 3)
		signal.Notify(rsig, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
		go func() {
			for s := range rsig {
				switch s {
				case syscall.SIGUSR1:
					log.Print("tnl-core: rotate-now (edge IP)")
					r.RotateIP()
				case syscall.SIGUSR2:
					log.Print("tnl-core: rotate-now (SNI)")
					r.RotateSNI()
				case syscall.SIGHUP:
					log.Print("tnl-core: probe-now (retest all suspect/dead edges)")
					r.ProbeAllNow()
				}
			}
		}()
	} else if r, ok := b.(interface{ ProbeAllNow() }); ok {
		// Direct-transport peer/source pool (udp/tcp/raw/flux): SIGHUP retests every suspect/dead
		// endpoint immediately (the "probe now" control). These carriers have no ws edge dimensions to
		// rotate, so only SIGHUP is wired; the else-if avoids double-registering it for the ws path.
		rsig := make(chan os.Signal, 1)
		signal.Notify(rsig, syscall.SIGHUP)
		go func() {
			for range rsig {
				log.Print("tnl-core: probe-now (retest all suspect/dead peer/source endpoints)")
				r.ProbeAllNow()
			}
		}()
	}

	if err := b.Run(); err != nil {
		log.Printf("tnl-core: stopped: %v", err)
	}
}

func coverTag(cover bool) string {
	if cover {
		return " tls"
	}
	return ""
}
