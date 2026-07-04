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

	var sealer packet.Sealer
	if cfg.Crypto.Enabled {
		s, err := crypto.NewSealer(cfg.Crypto.PSK)
		if err != nil {
			log.Fatalf("tnl-engine: crypto: %v", err)
		}
		sealer = s
	}

	dev, err := tun.Open(cfg.TunName, cfg.MTU, cfg.TunAddr)
	if err != nil {
		log.Fatalf("tnl-engine: tun: %v", err)
	}
	defer dev.Close()
	log.Printf("tnl-engine %s: tun=%s addr=%s mtu=%d crypto=%v role=%s",
		version, dev.Name, cfg.TunAddr, cfg.MTU, cfg.Crypto.Enabled, cfg.Role)

	var b *packet.Bip
	ka := time.Duration(cfg.Keepalive) * time.Second
	switch cfg.Role {
	case "server":
		b, err = packet.Listen(cfg.Listen, dev, sealer, ka)
		if err == nil {
			log.Printf("tnl-engine: listening (bip/udp) on %s", cfg.Listen)
		}
	case "client":
		b, err = packet.Dial(cfg.Peer, dev, sealer, ka)
		if err == nil {
			log.Printf("tnl-engine: dialing (bip/udp) %s", cfg.Peer)
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
