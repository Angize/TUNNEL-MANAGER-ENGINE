// Command tnl-engine is the custom data-plane engine for the tunnel fleet
// manager. This build implements a single slice: Mode "packet" / Profile "bip"
// — raw L3 packets over a TUN device, carried by UDP with optional AES-256-GCM.
//
// Usage:
//
//	tnl-engine --config /run/tnl/engine-<id>.json
//
// The node agent owns the config file; the engine just runs what it is told.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/packet"
	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/tun"
)

// version is stamped into logs so the panel can tell which engine a node runs.
const version = "0.1.0-bip"

func main() {
	cfgPath := flag.String("config", "", "path to engine JSON config")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		os.Stdout.WriteString(version + "\n")
		return
	}
	if *cfgPath == "" {
		log.Fatal("tnl-engine: --config is required")
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("tnl-engine: config: %v", err)
	}

	// Open the TUN device BEFORE building the sealer. The sealer's constructor may
	// draw from crypto/rand; on hosts without getrandom(2) that opens /dev/urandom
	// and registers it with the runtime netpoller, which can leave a subsequently
	// opened TUN fd in a half-pollable state (reads fail with "not pollable" and
	// the reader loop dies). Setting up the TUN first avoids that ordering hazard.
	dev, err := tun.Open(cfg.TunName, cfg.MTU, cfg.TunAddr)
	if err != nil {
		log.Fatalf("tnl-engine: tun: %v", err)
	}
	defer dev.Close()

	cipherName := "off"
	if cfg.Crypto.Enabled {
		// Validate the cipher/PSK up front (fail fast); the carriers build the
		// actual per-session sealers after the ephemeral handshake.
		s, err := crypto.NewSealer(cfg.Crypto.Cipher, cfg.Crypto.PSK, cfg.Role == "client")
		if err != nil {
			log.Fatalf("tnl-engine: crypto: %v", err)
		}
		cipherName = s.Name
	} else {
		if cfg.Obfs {
			log.Fatalf("tnl-engine: obfs requires crypto (there is no key to obfuscate with) — enable crypto or disable obfs")
		}
		// Clear mode has NO authentication: a single spoofed datagram can rebind
		// the peer or inject a packet into the TUN. Make that impossible to miss.
		log.Printf("tnl-engine: WARNING crypto is DISABLED — the tunnel is unauthenticated " +
			"and unencrypted; anyone who can send a packet to this listener can hijack or " +
			"inject into it. Enable crypto unless this is a trusted, isolated link.")
	}
	log.Printf("tnl-engine %s: tun=%s addr=%s mtu=%d cipher=%s role=%s",
		version, dev.Name, cfg.TunAddr, cfg.MTU, cipherName, cfg.Role)

	// carrier is satisfied by both the UDP (packet.Bip) and TCP (packet.BipTCP)
	// bip implementations; cfg.Transport selects which one is built.
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
	cryptoOn := cfg.Crypto.Enabled
	switch cfg.Transport {
	case "tcp":
		switch cfg.Role {
		case "server":
			b, err = packet.ListenTCP(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-engine: listening (bip/tcp%s%s) on %s", obfsTag, coverTag(cfg.Cover), cfg.Listen)
			}
		case "client":
			b, err = packet.DialTCP(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher, cfg.Cover, cfg.CoverSNI)
			if err == nil {
				log.Printf("tnl-engine: dialing (bip/tcp%s%s) %s", obfsTag, coverTag(cfg.Cover), cfg.Peer)
			}
		}
	default: // "udp"
		switch cfg.Role {
		case "server":
			b, err = packet.Listen(cfg.Listen, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher)
			if err == nil {
				log.Printf("tnl-engine: listening (bip/udp%s) on %s", obfsTag, cfg.Listen)
			}
		case "client":
			b, err = packet.Dial(cfg.Peer, dev, ka, cfg.Obfs, cryptoOn, cfg.Crypto.PSK, cfg.Crypto.Cipher)
			if err == nil {
				log.Printf("tnl-engine: dialing (bip/udp%s) %s", obfsTag, cfg.Peer)
			}
		}
	}
	if err != nil {
		log.Fatalf("tnl-engine: transport: %v", err)
	}
	defer b.Close()

	// Clean shutdown removes the TUN (via defers) on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("tnl-engine: shutting down")
		b.Close()
		dev.Close()
		os.Exit(0)
	}()

	if err := b.Run(); err != nil {
		log.Printf("tnl-engine: stopped: %v", err)
	}
}

func coverTag(cover bool) string {
	if cover {
		return " tls"
	}
	return ""
}
