// Package packet implements the "bip" carrier: raw L3 IP packets read from a
// TUN device, framed one-per-datagram, optionally AEAD-sealed, and shipped
// over UDP to the peer, which writes them into its own TUN.
//
// Wire format (one UDP datagram = one frame):
//
//	[0] magic = 0xB1               (legacy framing only; obfs framing has no magic)
//	[1] type  = 0 data | 1 ping | 2 pong
//	[2:] payload — sealed when crypto is on, raw when off
//
// Session establishment. When crypto is on the two ends first run an ephemeral
// X25519 handshake (see crypto.SessionSealer): the client sends a 48-byte init,
// the server replies, and both derive fresh per-session keys. Data flows only
// once that session exists. This gives forward secrecy and makes a captured
// old-session frame undecryptable under the new keys, so it can neither rebind
// the peer nor inject a packet. Handshake messages are demultiplexed from data by
// trial: a datagram that does not AEAD-open under the current session is tried as
// a handshake message (PSK-MAC authenticated); anything that is neither is
// dropped in silence. With crypto off there is no handshake and no authentication
// — a clear-mode tunnel offers no protection against a spoofed frame.
package packet

import (
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	magic byte = 0xB1

	typeData byte = 0
	typePing byte = 1
	typePong byte = 2

	maxDatagram = 65535
)

// Sealer is the subset of crypto.Sealer bip needs. Open returns the authenticated
// (session, seq) pair from the nonce so the carrier can reject replays before
// acting on a frame. aad carries the cleartext frame header (the type byte in
// legacy framing) so it is authenticated and cannot be flipped on the wire; obfs
// framing folds the type into the plaintext and passes nil.
type Sealer interface {
	Seal(pt, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) (session uint64, seq uint64, pt []byte, err error)
}

// sealerBox lets a *crypto.Sealer live in an atomic.Pointer.
type sealerBox struct{ s Sealer }

// Bip carries L3 packets between a TUN device and a UDP peer.
type Bip struct {
	conn      *net.UDPConn
	dev       *tun.Device
	keepalive time.Duration
	obfs      bool
	cryptoOn  bool
	psk       string
	cipher    string
	isClient  bool

	peer    atomic.Pointer[net.UDPAddr]      // current known peer (server learns it)
	session atomic.Pointer[sealerBox]        // negotiated session sealer (nil until handshake / clear mode)
	rp      replayGuard                      // driven only by netToTun (single receiver goroutine)
	ci      atomic.Pointer[crypto.Ephemeral] // client's current handshake ephemeral

	closeCh   chan struct{}
	closeOnce sync.Once
}

// Dial (client role) binds an ephemeral UDP socket and targets peerAddr.
func Dial(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string) (*Bip, error) {
	ra, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil) // ephemeral local port
	if err != nil {
		return nil, err
	}
	b := &Bip{conn: conn, dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, isClient: true, closeCh: make(chan struct{})}
	b.peer.Store(ra)
	return b, nil
}

// Listen (server role) binds listenAddr and waits to learn the peer.
func Listen(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string) (*Bip, error) {
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	return &Bip{conn: conn, dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, closeCh: make(chan struct{})}, nil
}

// Run blocks until one of the loops fails (e.g. the socket or device closes).
func (b *Bip) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- b.tunToNet() }()
	go func() { errc <- b.netToTun() }()
	if b.isClient {
		go b.clientLoop()
	}
	return <-errc
}

// Close tears down the socket (which unblocks both loops) and stops the client
// loop. Safe to call more than once.
func (b *Bip) Close() error {
	b.closeOnce.Do(func() { close(b.closeCh) })
	return b.conn.Close()
}

func (b *Bip) sealer() Sealer {
	if box := b.session.Load(); box != nil {
		return box.s
	}
	return nil
}

// frame builds one datagram for typ/payload using the current session sealer
// (or clear framing when crypto is off / no session yet).
func (b *Bip) frame(typ byte, payload []byte) ([]byte, error) {
	s := b.sealer()
	if b.obfs {
		return obfsSeal(s, typ, payload, padMaxFor(typ))
	}
	if s != nil {
		sealed, err := s.Seal(payload, []byte{typ}) // authenticate the type byte
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

// tunToNet reads L3 packets from TUN, seals them, and sends to the peer. Packets
// read before a session exists (crypto on, handshake not yet complete) are
// dropped; the peer retransmits at L4.
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
		if b.cryptoOn && b.sealer() == nil {
			continue // handshake not finished yet; drop (L4 will retransmit)
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
// known peer, and writes data frames into the TUN. Datagrams that do not open
// under the current session are tried as handshake messages.
func (b *Bip) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if b.cryptoOn {
			b.handleCrypto(buf[:n], addr)
			continue
		}
		// clear mode: unauthenticated legacy framing
		if n < 2 || buf[0] != magic {
			continue
		}
		b.peer.Store(addr)
		b.dispatch(buf[1], iff(buf[1] == typeData, buf[2:n], nil), addr)
	}
}

// handleCrypto is the crypto-on receive path: try the frame as data under the
// current session; failing that, try it as a handshake message.
func (b *Bip) handleCrypto(pkt []byte, addr *net.UDPAddr) {
	if s := b.sealer(); s != nil {
		var (
			typ          byte
			session, seq uint64
			payload      []byte
			oerr         error
		)
		if b.obfs {
			typ, session, seq, payload, oerr = obfsOpen(s, pkt)
		} else if len(pkt) >= 2 && pkt[0] == magic {
			typ = pkt[1]
			session, seq, payload, oerr = s.Open(pkt[2:], []byte{typ})
		} else {
			oerr = errBadFrame
		}
		if oerr == nil && b.rp.ok(session, seq) {
			// authenticated, fresh frame -> now safe to (re)learn the peer address
			b.peer.Store(addr)
			b.dispatch(typ, payload, addr)
			return
		}
		// fall through: maybe this is a re-handshake from a restarted peer
	}
	b.tryHandshake(pkt, addr)
}

// tryHandshake demuxes a datagram that did not open as data. On the server an
// init starts a fresh session; on the client a resp completes ours.
func (b *Bip) tryHandshake(pkt []byte, addr *net.UDPAddr) {
	if b.isClient {
		ci := b.ci.Load()
		if ci == nil {
			return
		}
		eResp, err := crypto.ParseResp(b.psk, ci.Pub, pkt)
		if err != nil {
			return
		}
		s, err := crypto.SessionSealer(b.cipher, b.psk, ci, eResp, ci.Pub, eResp, true)
		if err != nil {
			return
		}
		b.rp = replayGuard{}
		b.session.Store(&sealerBox{s: s})
		return
	}
	// server: authenticate an init, reply, and install the fresh session.
	eInit, err := crypto.ParseInit(b.psk, pkt)
	if err != nil {
		return
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	s, err := crypto.SessionSealer(b.cipher, b.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return
	}
	b.rp = replayGuard{}
	b.session.Store(&sealerBox{s: s})
	// Reply to the init source, but do NOT rebind the tunnel here — rebinding
	// waits for a data/ping frame that opens under the new session, so a replayed
	// init cannot redirect traffic.
	if msg2 := crypto.RespMsg(b.psk, eInit, sr); msg2 != nil {
		_, _ = b.conn.WriteToUDP(msg2, addr)
	}
}

func (b *Bip) dispatch(typ byte, payload []byte, addr *net.UDPAddr) {
	switch typ {
	case typePing:
		b.send(typePong, nil, addr)
	case typePong:
		// keepalive ack
	case typeData:
		if _, err := b.dev.Write(payload); err != nil {
			log.Printf("bip: tun write error: %v", err)
		}
	}
}

// clientLoop (client) drives the handshake and keepalives: it (re)sends an init
// until a session exists, then pings on a jittered interval. If the session is
// lost it starts a new handshake.
func (b *Bip) clientLoop() {
	for {
		if b.sealer() == nil && b.cryptoOn {
			b.sendInit()
		} else {
			b.send(typePing, nil, b.peer.Load())
		}
		wait := b.keepalive
		if b.sealer() == nil && b.cryptoOn {
			wait = time.Second // retransmit the handshake faster than keepalive
		} else {
			wait = jitter(wait)
		}
		select {
		case <-b.closeCh:
			return
		case <-time.After(wait):
		}
	}
}

func (b *Bip) sendInit() {
	peer := b.peer.Load()
	if peer == nil {
		return
	}
	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	b.ci.Store(ci)
	_, _ = b.conn.WriteToUDP(crypto.InitMsg(b.psk, ci), peer)
}

func (b *Bip) send(typ byte, payload []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	if b.cryptoOn && b.sealer() == nil {
		return // no session yet
	}
	frame, err := b.frame(typ, payload)
	if err != nil {
		return
	}
	_, _ = b.conn.WriteToUDP(frame, to)
}

func iff(cond bool, a, b []byte) []byte {
	if cond {
		return a
	}
	return b
}

var errBadFrame = errors.New("bip: bad frame")

// ErrClosed is returned by Run when the connection was closed intentionally.
var ErrClosed = errors.New("bip: closed")
