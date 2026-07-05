// Package packet implements the "bip" carrier: raw L3 IP packets read from a
// TUN device, framed one-per-datagram, optionally AEAD-sealed, and shipped
// over UDP to the peer, which writes them into its own TUN.
//
// Wire format (one UDP datagram = one frame):
//
//	[0] magic = 0xB1
//	[1] type  = 0 data | 1 ping | 2 pong
//	[2:] payload
//	        crypto on:  sealed(nonce||ct) for EVERY type (ping/pong seal an empty
//	                    payload) so control frames are authenticated too
//	        crypto off: the raw IP packet for data, empty for ping/pong
//
// Authentication and the peer address: the server learns the client's address
// from the frames it receives (works through NAT), but ONLY after a frame both
// AEAD-opens and passes the anti-replay window. With crypto off there is nothing
// to authenticate, so the peer is taken on faith — a clear-mode tunnel offers no
// protection against a spoofed control frame; run crypto (the panel does by
// default) to get peer-rebinding protection.
//
// Roles: the "server" binds a UDP socket and learns the peer's address as above.
// The "client" dials the server and sends a ping every keepalive interval so the
// server always knows where to send return traffic even when no L3 packets flow.
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
// Open returns the authenticated (session, seq) pair from the nonce so the
// carrier can reject replays before acting on a frame.
type Sealer interface {
	Seal(pt []byte) ([]byte, error)
	Open(sealed []byte) (session uint64, seq uint64, pt []byte, err error)
}

// Bip carries L3 packets between a TUN device and a UDP peer.
type Bip struct {
	conn      *net.UDPConn
	dev       *tun.Device
	sealer    Sealer
	keepalive time.Duration
	obfs      bool // anti-DPI framing: no magic, folded type, padding, jitter

	peer     atomic.Pointer[net.UDPAddr] // current known peer (server learns it)
	isClient bool
	rp       replayGuard // driven only by netToTun (single receiver goroutine)
}

// Dial (client role) binds an ephemeral UDP socket and targets peerAddr.
func Dial(peerAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration, obfs bool) (*Bip, error) {
	ra, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil) // ephemeral local port
	if err != nil {
		return nil, err
	}
	b := &Bip{conn: conn, dev: dev, sealer: sealer, keepalive: keepalive, obfs: obfs, isClient: true}
	b.peer.Store(ra)
	return b, nil
}

// Listen (server role) binds listenAddr and waits to learn the peer.
func Listen(listenAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration, obfs bool) (*Bip, error) {
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	return &Bip{conn: conn, dev: dev, sealer: sealer, keepalive: keepalive, obfs: obfs}, nil
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

// frame builds one datagram for typ/payload. With crypto on every type is
// sealed (ping/pong seal an empty payload) so control frames are authenticated;
// with crypto off it is the legacy [magic][type][payload].
func (b *Bip) frame(typ byte, payload []byte) ([]byte, error) {
	if b.obfs {
		return obfsSeal(b.sealer, typ, payload, padMaxFor(typ))
	}
	if b.sealer != nil {
		sealed, err := b.sealer.Seal(payload)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 2+len(sealed))
		out[0], out[1] = magic, typ
		copy(out[2:], sealed)
		return out, nil
	}
	out := make([]byte, 2+len(payload))
	out[0], out[1] = magic, typ
	copy(out[2:], payload)
	return out, nil
}

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
		frame, err := b.frame(typeData, buf[:n])
		if err != nil {
			log.Printf("bip: seal error: %v", err)
			continue
		}
		if _, err := b.conn.WriteToUDP(frame, peer); err != nil {
			log.Printf("bip: write error: %v", err)
		}
	}
}

// netToTun receives datagrams, authenticates them, rejects replays, updates the
// known peer, and writes data frames into the TUN.
func (b *Bip) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		var (
			typ     byte
			payload []byte
		)
		if b.obfs {
			// The only "is this ours?" test is a successful AEAD open + a fresh
			// sequence number. Garbage (a DPI probe, wrong PSK) or a replayed
			// capture fails and is dropped with no response — the server never
			// emits an identifying byte to a stranger, nor rebinds to a replay.
			t, session, seq, pt, oerr := obfsOpen(b.sealer, buf[:n])
			if oerr != nil || !b.rp.ok(session, seq) {
				continue
			}
			typ, payload = t, pt
		} else {
			if n < 2 || buf[0] != magic {
				continue // not ours
			}
			typ = buf[1]
			if b.sealer != nil {
				session, seq, pt, oerr := b.sealer.Open(buf[2:n])
				if oerr != nil || !b.rp.ok(session, seq) {
					continue // auth failure or replay -> do NOT rebind the peer
				}
				payload = pt
			} else if typ == typeData {
				payload = buf[2:n] // clear mode: unauthenticated
			}
		}
		// An authenticated, non-replayed frame tells us where the peer now is.
		b.peer.Store(addr)
		switch typ {
		case typePing:
			b.send(typePong, nil, addr)
		case typePong:
			// keepalive ack; nothing else to do
		case typeData:
			if _, err := b.dev.Write(payload); err != nil {
				log.Printf("bip: tun write error: %v", err)
			}
		}
	}
}

func (b *Bip) keepaliveLoop() {
	b.send(typePing, nil, b.peer.Load()) // prime immediately
	for {
		d := b.keepalive
		if b.obfs {
			d = jitter(d) // break the fixed keepalive period
		}
		time.Sleep(d)
		if peer := b.peer.Load(); peer != nil {
			b.send(typePing, nil, peer)
		}
	}
}

func (b *Bip) send(typ byte, payload []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	frame, err := b.frame(typ, payload)
	if err != nil {
		return
	}
	_, _ = b.conn.WriteToUDP(frame, to)
}

// ErrClosed is returned by Run when the connection was closed intentionally.
var ErrClosed = errors.New("bip: closed")
