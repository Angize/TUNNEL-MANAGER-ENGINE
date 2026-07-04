// Package packet implements the "bip" carrier: raw L3 IP packets read from a
// TUN device, framed one-per-datagram, optionally AEAD-sealed, and shipped
// over UDP to the peer, which writes them into its own TUN.
//
// Wire format (one UDP datagram = one frame):
//
//	[0] magic = 0xB1
//	[1] type  = 0 data | 1 ping | 2 pong
//	[2:] payload
//	        data: sealed(nonce||ct) if crypto on, else the raw IP packet
//	        ping/pong: empty
//
// Roles: the "server" binds a UDP socket and learns the peer's address from
// the first packet it receives (works through NAT). The "client" dials the
// server and sends a ping every keepalive interval so the server always knows
// where to send return traffic even when no L3 packets are flowing.
package packet

import (
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/tun"
)

const (
	magic byte = 0xB1

	typeData byte = 0
	typePing byte = 1
	typePong byte = 2

	maxDatagram = 65535
)

// Sealer is the subset of crypto.Sealer bip needs (nil means crypto off).
type Sealer interface {
	Seal(pt []byte) ([]byte, error)
	Open(ct []byte) ([]byte, error)
}

// Bip carries L3 packets between a TUN device and a UDP peer.
type Bip struct {
	conn      *net.UDPConn
	dev       *tun.Device
	sealer    Sealer
	keepalive time.Duration

	peer   atomic.Pointer[net.UDPAddr] // current known peer (server learns it)
	isClient bool
}

// Dial (client role) binds an ephemeral UDP socket and targets peerAddr.
func Dial(peerAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration) (*Bip, error) {
	ra, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil) // ephemeral local port
	if err != nil {
		return nil, err
	}
	b := &Bip{conn: conn, dev: dev, sealer: sealer, keepalive: keepalive, isClient: true}
	b.peer.Store(ra)
	return b, nil
}

// Listen (server role) binds listenAddr and waits to learn the peer.
func Listen(listenAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration) (*Bip, error) {
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	return &Bip{conn: conn, dev: dev, sealer: sealer, keepalive: keepalive}, nil
}

// Run blocks until one of the loops fails (e.g. the socket or device closes).
func (b *Bip) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- b.tunToNet() }()
	go func() { errc <- b.netToTun() }()
	if b.isClient {
		go b.keepaliveLoop()
	}
	return <-errc
}

// Close tears down the socket, which unblocks both loops.
func (b *Bip) Close() error { return b.conn.Close() }

// tunToNet reads L3 packets from TUN, seals them, and sends to the peer.
func (b *Bip) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := b.peer.Load()
		if peer == nil {
			continue // server has not learned the client yet; drop
		}
		payload := buf[:n]
		if b.sealer != nil {
			sealed, err := b.sealer.Seal(payload)
			if err != nil {
				log.Printf("bip: seal error: %v", err)
				continue
			}
			payload = sealed
		}
		frame := make([]byte, 2+len(payload))
		frame[0] = magic
		frame[1] = typeData
		copy(frame[2:], payload)
		if _, err := b.conn.WriteToUDP(frame, peer); err != nil {
			log.Printf("bip: write error: %v", err)
		}
	}
}

// netToTun receives datagrams, updates the known peer, and writes data frames
// into the TUN.
func (b *Bip) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n < 2 || buf[0] != magic {
			continue // not ours
		}
		// Any valid frame tells us where the peer currently is.
		b.peer.Store(addr)
		switch buf[1] {
		case typePing:
			b.send(typePong, nil, addr)
		case typePong:
			// keepalive ack; nothing else to do
		case typeData:
			payload := buf[2:n]
			if b.sealer != nil {
				opened, err := b.sealer.Open(payload)
				if err != nil {
					log.Printf("bip: open error (auth fail?): %v", err)
					continue
				}
				payload = opened
			}
			if _, err := b.dev.Write(payload); err != nil {
				log.Printf("bip: tun write error: %v", err)
			}
		}
	}
}

func (b *Bip) keepaliveLoop() {
	t := time.NewTicker(b.keepalive)
	defer t.Stop()
	b.send(typePing, nil, b.peer.Load()) // prime immediately
	for range t.C {
		if peer := b.peer.Load(); peer != nil {
			b.send(typePing, nil, peer)
		}
	}
}

func (b *Bip) send(typ byte, payload []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	frame := make([]byte, 2+len(payload))
	frame[0] = magic
	frame[1] = typ
	copy(frame[2:], payload)
	_, _ = b.conn.WriteToUDP(frame, to)
}

// ErrClosed is returned by Run when the connection was closed intentionally.
var ErrClosed = errors.New("bip: closed")
