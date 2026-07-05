// This file implements the "bip" carrier over TCP. It mirrors bip.go (same
// type frame and Sealer contract) but adapts to a byte stream.
//
// Legacy framing (obfs off) — length-prefixed so the reader can reframe:
//
//	[0:2] uint16 big-endian N = length of the frame that follows (magic+type+payload)
//	[2]   magic = 0xB1
//	[3]   type  = 0 data | 1 ping | 2 pong
//	[4:]  payload — when crypto is on this is sealed(nonce||ct) for EVERY type
//	      (ping/pong seal an empty payload) so control frames are authenticated;
//	      with crypto off it is the raw IP packet for data, empty for ping/pong
//
// Obfs framing (obfs on) — no constant bytes on the wire:
//
//	handshake: each side writes a 24-byte random salt, then reads the peer's.
//	per frame: [0:2] uint16 length XOR ChaCha20-keystream(PSK,salt)
//	           [2:]  AEAD-sealed [type][realLen][payload][random-pad]
//
// Roles: the "server" listens and accepts; the "client" dials and reconnects
// automatically with a short backoff. Because a bip tunnel is a single
// point-to-point link, only one connection is active at a time — a new accepted
// connection replaces (and closes) the previous one. A single TUN reader feeds
// whichever connection is currently live via an atomic pointer, so no L3 packet
// is bound to a connection that may have dropped.
package packet

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/tun"
)

const maxFrame = 65535 // uint16 length prefix ceiling (payload fits far under this)

var errDesync = errors.New("bip/tcp: stream desync")

// connFramer wraps a stream connection and owns the seal<->frame transform in
// both directions. A write lock lets the TUN reader and the keepalive loop emit
// frames without interleaving bytes (and, in obfs mode, without racing the
// stateful length keystream).
type connFramer struct {
	conn   net.Conn
	r      *bufio.Reader
	mu     sync.Mutex
	sealer Sealer
	obfs   bool
	psk    string

	// obfs length-prefix keystreams (nil until established). writeKS is keyed by
	// the salt we sent, readKS by the salt the peer sent (read lazily on the
	// first frame). saltSent guards the one-time salt emission.
	writeKS  *chacha20.Cipher
	readKS   *chacha20.Cipher
	saltSent bool
}

// sendSalt emits our per-connection salt once and arms the write keystream.
// The server calls it only AFTER it has authenticated the client's first frame,
// so a peer that does not know the PSK gets zero bytes back (probe resistance).
func (cf *connFramer) sendSalt() error {
	if cf.saltSent {
		return nil
	}
	salt := make([]byte, obfsSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	ws, err := newObfsStream(cf.psk, salt)
	if err != nil {
		return err
	}
	cf.mu.Lock()
	_, werr := cf.conn.Write(salt)
	if werr == nil {
		cf.writeKS = ws
		cf.saltSent = true
	}
	cf.mu.Unlock()
	return werr
}

// ensureReadKS reads the peer's salt (once) and arms the read keystream.
func (cf *connFramer) ensureReadKS() error {
	if cf.readKS != nil {
		return nil
	}
	peer := make([]byte, obfsSaltLen)
	if _, err := io.ReadFull(cf.r, peer); err != nil {
		return err
	}
	rs, err := newObfsStream(cf.psk, peer)
	if err != nil {
		return err
	}
	cf.readKS = rs
	return nil
}

// writeFrame seals payload and writes one framed message.
func (cf *connFramer) writeFrame(typ byte, payload []byte) error {
	if cf.obfs {
		sealed, err := obfsSeal(cf.sealer, typ, payload, padMaxFor(typ))
		if err != nil {
			return err
		}
		if len(sealed) > maxFrame {
			return io.ErrShortWrite
		}
		out := make([]byte, 2+len(sealed))
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(sealed)))
		copy(out[2:], sealed)
		cf.mu.Lock()
		cf.writeKS.XORKeyStream(out[0:2], lb[:]) // mask length; advances keystream
		_, err = cf.conn.Write(out)
		cf.mu.Unlock()
		return err
	}

	// Legacy: [len][magic][type][sealed]. With crypto on we seal EVERY type
	// (ping/pong seal an empty payload) so control frames are authenticated.
	sealed := payload
	if cf.sealer != nil {
		s, err := cf.sealer.Seal(payload)
		if err != nil {
			return err
		}
		sealed = s
	}
	n := 2 + len(sealed)
	if n > maxFrame {
		return io.ErrShortWrite
	}
	out := make([]byte, 2+n)
	binary.BigEndian.PutUint16(out[0:2], uint16(n))
	out[2] = magic
	out[3] = typ
	copy(out[4:], sealed)
	cf.mu.Lock()
	_, err := cf.conn.Write(out)
	cf.mu.Unlock()
	return err
}

// readFrame reads one framed message and returns its type, the sender's
// (session, seq) for anti-replay, and the real payload (padding stripped, data
// unsealed). ping/pong carry a nil/empty payload. session/seq are 0 in clear
// mode (no crypto), where replay cannot be detected.
func (cf *connFramer) readFrame() (typ byte, session uint64, seq uint64, payload []byte, err error) {
	if cf.obfs {
		if err := cf.ensureReadKS(); err != nil { // peer salt precedes its frames
			return 0, 0, 0, nil, err
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(cf.r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	if cf.obfs {
		var lb [2]byte
		cf.readKS.XORKeyStream(lb[:], hdr[:]) // unmask length; advances keystream
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 1 || n > maxFrame {
			return 0, 0, 0, nil, errDesync
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(cf.r, buf); err != nil {
			return 0, 0, 0, nil, err
		}
		return obfsOpen(cf.sealer, buf)
	}

	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 2 {
		return 0, 0, 0, nil, errDesync
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(cf.r, buf); err != nil {
		return 0, 0, 0, nil, err
	}
	if buf[0] != magic {
		return 0, 0, 0, nil, errDesync
	}
	typ = buf[1]
	if cf.sealer != nil { // crypto on: every type is sealed and authenticated
		session, seq, payload, err = cf.sealer.Open(buf[2:n])
		if err != nil {
			return 0, 0, 0, nil, err
		}
		return typ, session, seq, payload, nil
	}
	if typ == typeData { // clear mode: only data carries a payload
		return typ, 0, 0, buf[2:n], nil
	}
	return typ, 0, 0, nil, nil
}

// BipTCP carries L3 packets between a TUN device and a TCP peer.
type BipTCP struct {
	dev       *tun.Device
	sealer    Sealer
	keepalive time.Duration
	obfs      bool
	psk       string
	idle      time.Duration // read deadline; reaps dead/probe connections

	isClient bool
	addr     string // server: listen addr; client: peer addr

	ln      net.Listener
	cur     atomic.Pointer[connFramer] // currently live connection (nil when none)
	closed  atomic.Bool
	closeCh chan struct{}
	rp      atomicReplayGuard // inbound anti-replay, shared across (re)connections
}

func idleFor(keepalive time.Duration) time.Duration {
	d := 4 * keepalive
	if d < 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

// DialTCP (client role) targets peerAddr and reconnects on drop.
func DialTCP(peerAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration, obfs bool, psk string) (*BipTCP, error) {
	return &BipTCP{dev: dev, sealer: sealer, keepalive: keepalive, obfs: obfs, psk: psk,
		idle: idleFor(keepalive), isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// ListenTCP (server role) binds listenAddr and accepts connections.
func ListenTCP(listenAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration, obfs bool, psk string) (*BipTCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &BipTCP{dev: dev, sealer: sealer, keepalive: keepalive, obfs: obfs, psk: psk,
		idle: idleFor(keepalive), addr: listenAddr, ln: ln, closeCh: make(chan struct{})}, nil
}

// Run blocks until Close is called. The TUN reader runs for the whole lifetime;
// the connection side either accepts (server) or dials-with-retry (client).
func (b *BipTCP) Run() error {
	go b.tunLoop()
	if b.isClient {
		go b.keepaliveLoop()
		b.dialLoop()
	} else {
		b.acceptLoop()
	}
	return nil
}

// Close stops the carrier and unblocks Run.
func (b *BipTCP) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	close(b.closeCh)
	if b.ln != nil {
		b.ln.Close()
	}
	if c := b.cur.Load(); c != nil {
		c.conn.Close()
	}
	return nil
}

func (b *BipTCP) newFramer(conn net.Conn) *connFramer {
	return &connFramer{conn: conn, r: bufio.NewReaderSize(conn, maxFrame+2), sealer: b.sealer, obfs: b.obfs, psk: b.psk}
}

// acceptLoop (server) hands each new connection to a per-connection goroutine.
func (b *BipTCP) acceptLoop() {
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			if b.closed.Load() {
				return
			}
			log.Printf("bip/tcp: accept error: %v", err)
			continue
		}
		go b.handleServerConn(conn)
	}
}

// handleServerConn serves one accepted connection. Whenever crypto is on (obfs
// or plain TCP) the connection is authenticated BEFORE it is published as live:
// the first frame must AEAD-open and pass anti-replay, so an unauthenticated
// peer (a probe, a port scan, `nc`) can no longer evict the real client by
// simply connecting. In obfs mode the salt is also withheld until then, so the
// server stays invisible to an active probe. Only clear mode (no crypto) — which
// offers no authentication by definition — publishes at once.
func (b *BipTCP) handleServerConn(conn net.Conn) {
	cf := b.newFramer(conn)
	if b.sealer == nil {
		log.Printf("bip/tcp: peer connected from %s (clear)", conn.RemoteAddr())
		if old := b.cur.Swap(cf); old != nil {
			old.conn.Close()
		}
		b.serve(cf)
		return
	}
	// crypto on: read+authenticate the first frame silently before revealing or
	// publishing anything. A wrong PSK or a replayed capture is dropped in silence.
	conn.SetReadDeadline(time.Now().Add(b.idle))
	typ, session, seq, payload, err := cf.readFrame()
	if err != nil || !b.rp.ok(session, seq) {
		conn.Close() // probe / wrong PSK / replay: no reply, no log noise
		return
	}
	if b.obfs {
		if err := cf.sendSalt(); err != nil { // authenticated — now answer
			conn.Close()
			return
		}
	}
	log.Printf("bip/tcp: peer connected from %s", conn.RemoteAddr())
	if old := b.cur.Swap(cf); old != nil {
		old.conn.Close()
	}
	b.handleFrame(cf, typ, payload)
	b.serve(cf)
}

// dialLoop (client) keeps a connection to the server alive, retrying on drop.
func (b *BipTCP) dialLoop() {
	for {
		if b.closed.Load() {
			return
		}
		conn, err := net.DialTimeout("tcp", b.addr, 10*time.Second)
		if err != nil {
			log.Printf("bip/tcp: dial %s failed: %v", b.addr, err)
			if b.sleep(1 * time.Second) {
				return
			}
			continue
		}
		cf := b.newFramer(conn)
		if b.obfs {
			conn.SetReadDeadline(time.Now().Add(b.idle))
			if err := cf.sendSalt(); err != nil { // client speaks first
				conn.Close()
				if b.sleep(1 * time.Second) {
					return
				}
				continue
			}
		}
		log.Printf("bip/tcp: connected to %s", b.addr)
		b.cur.Store(cf)
		_ = cf.writeFrame(typePing, nil) // prime + authenticate us to the server
		b.serve(cf)                // blocks until this connection dies
		b.cur.CompareAndSwap(cf, nil)
		if b.sleep(1 * time.Second) {
			return
		}
	}
}

// handleFrame dispatches a single decoded frame.
func (b *BipTCP) handleFrame(cf *connFramer, typ byte, payload []byte) {
	switch typ {
	case typePing:
		_ = cf.writeFrame(typePong, nil)
	case typePong:
		// keepalive ack
	case typeData:
		if _, err := b.dev.Write(payload); err != nil {
			log.Printf("bip/tcp: tun write error: %v", err)
		}
	}
}

// serve reads framed messages from one connection until it errors or closes.
// onConnErr clears the live pointer on exit, so both the client (which redials)
// and the server converge on "no live connection" without extra bookkeeping.
// The read deadline is refreshed every frame in ALL modes so a peer that dies
// without a FIN/RST is reaped instead of pinning a goroutine forever.
func (b *BipTCP) serve(cf *connFramer) {
	for {
		cf.conn.SetReadDeadline(time.Now().Add(b.idle))
		typ, session, seq, payload, err := cf.readFrame()
		if err != nil {
			b.onConnErr(cf, err)
			return
		}
		if cf.sealer != nil && !b.rp.ok(session, seq) {
			continue // authenticated but replayed -> ignore, keep the connection
		}
		b.handleFrame(cf, typ, payload)
	}
}

func (b *BipTCP) onConnErr(cf *connFramer, err error) {
	cf.conn.Close()
	b.cur.CompareAndSwap(cf, nil)
	if !b.closed.Load() {
		log.Printf("bip/tcp: connection closed: %v", err)
	}
}

// tunLoop reads L3 packets from TUN and writes them to whichever connection is
// currently live. Packets that arrive while no connection is up are dropped
// (the peer retransmits at the L4 layer).
func (b *BipTCP) tunLoop() {
	buf := make([]byte, maxDatagram)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			if !b.closed.Load() {
				log.Printf("bip/tcp: tun read error: %v", err)
			}
			return
		}
		cf := b.cur.Load()
		if cf == nil {
			continue // no live peer connection yet
		}
		if err := cf.writeFrame(typeData, buf[:n]); err != nil {
			b.onConnErr(cf, err)
		}
	}
}

// keepaliveLoop (client) pings the server over the live connection so idle
// tunnels do not get reaped by stateful middleboxes. In obfs mode the period is
// jittered so it does not emit on a fixed clock.
func (b *BipTCP) keepaliveLoop() {
	for {
		d := b.keepalive
		if b.obfs {
			d = jitter(d)
		}
		select {
		case <-b.closeCh:
			return
		case <-time.After(d):
			if cf := b.cur.Load(); cf != nil {
				if err := cf.writeFrame(typePing, nil); err != nil {
					b.onConnErr(cf, err)
				}
			}
		}
	}
}

// sleep waits d or returns true if Close fired during the wait.
func (b *BipTCP) sleep(d time.Duration) bool {
	select {
	case <-b.closeCh:
		return true
	case <-time.After(d):
		return false
	}
}
