//go:build linux

// This file implements the "raw" transport: the same bip frames as the UDP
// carrier (bip.go), but each frame is wrapped in a raw-IP profile header
// (rawEncap) and shipped over a raw IPv4 socket of the profile's protocol
// number instead of over UDP. It mirrors Bip's structure — ephemeral X25519
// handshake, replay guard, obfs and clear/crypto modes — so only the socket and
// the per-frame profile wrap differ.
//
// A raw socket needs CAP_NET_RAW (root). Because it receives EVERY packet of the
// chosen protocol addressed to the host, frames are filtered by peer source
// address and then authenticated by the inner AEAD; anything else is dropped.
package packet

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// Raw carries L3 packets between a TUN device and a peer over a raw IPv4 socket.
type Raw struct {
	conn      *net.IPConn
	dev       *tun.Device
	keepalive time.Duration
	obfs      bool
	cryptoOn  bool
	psk       string
	cipher    string
	profile   string
	isClient  bool
	icmpID    uint16 // per-process ICMP echo identifier (receiver ignores it)

	// Source-IP spoofing (client): forge the outer IPv4 source so per-source/stateful
	// egress filters can't pin the real IP. spoofFd is a SOCK_RAW+IP_HDRINCL socket used
	// to build the whole IP header ourselves; the ordinary conn still RECEIVES replies
	// (which come back to our real IP). On the SERVER, fixedPeer is the client's REAL IP
	// (the reply target) — needed because the packet source is forged, so the server
	// can't learn it; it also disables the source filter (the AEAD still authenticates).
	proto     int
	spoofSrc  net.IP
	spoofFd   int
	fixedPeer net.IP

	localIP atomic.Pointer[net.IPAddr] // our source IP toward the peer (for TCP/UDP checksums)
	peer    atomic.Pointer[net.IPAddr] // current known peer (server learns it)
	session atomic.Pointer[sealerBox]
	rp      replayGuard
	ci      atomic.Pointer[crypto.Ephemeral]
	seq     atomic.Uint32

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newRaw(conn *net.IPConn, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, isClient bool) *Raw {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	return &Raw{
		conn: conn, dev: dev, keepalive: ka, obfs: obfs, cryptoOn: cryptoOn,
		psk: psk, cipher: cipher, profile: profile, isClient: isClient, spoofFd: -1,
		icmpID: binary.BigEndian.Uint16(idb[:]), closeCh: make(chan struct{}),
	}
}

// DialRaw (client role) opens a raw socket of the profile's protocol and targets
// peerIP. peerIP may be a plain IPv4 or an "ip:port" (the port is ignored — raw
// IP has no ports of its own; the tcp/udp profiles carry synthetic ones).
func DialRaw(peerIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile, spoofSrc string) (*Raw, error) {
	proto, ok := rawProtoFor(profile)
	if !ok {
		return nil, fmt.Errorf("raw: unknown profile %q", profile)
	}
	ip := parseIP4(hostOnly(peerIP))
	if ip == nil {
		return nil, fmt.Errorf("raw: peer %q is not an IPv4 address", peerIP)
	}
	conn, err := net.ListenIP("ip4:"+strconv.Itoa(proto), &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	r := newRaw(conn, dev, ka, obfs, cryptoOn, psk, cipher, profile, true)
	r.proto = proto
	r.peer.Store(&net.IPAddr{IP: ip})
	if lip := routeLocalIP(ip); lip != nil {
		r.localIP.Store(&net.IPAddr{IP: lip})
	}
	if spoofSrc != "" { // forge the outer source; conn still receives replies at our real IP
		sip := parseIP4(spoofSrc)
		if sip == nil {
			conn.Close()
			return nil, fmt.Errorf("raw: spoof_src_ip %q is not an IPv4 address", spoofSrc)
		}
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("raw: spoof socket: %w", err)
		}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			conn.Close()
			return nil, fmt.Errorf("raw: set IP_HDRINCL: %w", err)
		}
		r.spoofSrc, r.spoofFd = sip, fd
	}
	return r, nil
}

// ListenRaw (server role) binds a raw socket of the profile's protocol and waits
// to learn the peer from the first authenticated frame. listenIP may be empty,
// "0.0.0.0", a plain IPv4, or an "ip:port" (the port is ignored).
func ListenRaw(listenIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile, spoofPeer string) (*Raw, error) {
	proto, ok := rawProtoFor(profile)
	if !ok {
		return nil, fmt.Errorf("raw: unknown profile %q", profile)
	}
	bind := net.IPv4zero
	if h := hostOnly(listenIP); h != "" && h != "0.0.0.0" {
		if ip := parseIP4(h); ip != nil {
			bind = ip
		}
	}
	conn, err := net.ListenIP("ip4:"+strconv.Itoa(proto), &net.IPAddr{IP: bind})
	if err != nil {
		return nil, err
	}
	r := newRaw(conn, dev, ka, obfs, cryptoOn, psk, cipher, profile, false)
	r.proto = proto
	if spoofPeer != "" { // client forges its source, so we can't learn it — reply to this real IP
		pip := parseIP4(hostOnly(spoofPeer))
		if pip == nil {
			conn.Close()
			return nil, fmt.Errorf("raw: spoof_peer %q is not an IPv4 address", spoofPeer)
		}
		r.fixedPeer = pip
		r.peer.Store(&net.IPAddr{IP: pip})
		if lip := routeLocalIP(pip); lip != nil {
			r.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	return r, nil
}

// Run blocks until one of the loops fails (e.g. the socket or device closes).
func (r *Raw) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- r.tunToNet() }()
	go func() { errc <- r.netToTun() }()
	if r.isClient {
		go r.clientLoop()
	}
	return <-errc
}

// Close tears down the socket (unblocking both loops) and the client loop.
func (r *Raw) Close() error {
	r.closeOnce.Do(func() { close(r.closeCh) })
	if r.spoofFd >= 0 {
		syscall.Close(r.spoofFd)
	}
	return r.conn.Close()
}

func (r *Raw) sealer() Sealer {
	if box := r.session.Load(); box != nil {
		return box.s
	}
	return nil
}

func (r *Raw) srcIP() net.IP {
	if l := r.localIP.Load(); l != nil {
		return l.IP
	}
	return net.IPv4zero
}

// body builds the framed (magic/type/sealed or obfs) bytes for typ/payload —
// identical to the UDP carrier's frame() — before the profile wrap is applied.
func (r *Raw) body(typ byte, payload []byte) ([]byte, error) {
	s := r.sealer()
	if r.obfs {
		return obfsSeal(s, typ, payload, padMaxFor(typ))
	}
	if s != nil {
		sealed, err := s.Seal(payload, []byte{typ})
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

// wire wraps a framed body in the profile carrier header, ready for the socket.
func (r *Raw) wire(body []byte, dst net.IP) []byte {
	return rawEncap(r.profile, body, r.srcIP(), dst, r.isClient, r.icmpID, r.seq.Add(1))
}

// writeOut sends one wrapped packet to `to`. When source spoofing is on (client)
// it builds the whole IPv4 header via the IP_HDRINCL socket so the outer source
// is the forged address; otherwise the kernel builds the header on the IPConn.
func (r *Raw) writeOut(pkt []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	if r.spoofSrc != nil && r.spoofFd >= 0 {
		out := buildIP4(r.spoofSrc, to.IP, r.proto, pkt)
		var sa syscall.SockaddrInet4
		copy(sa.Addr[:], to.IP.To4())
		_ = syscall.Sendto(r.spoofFd, out, 0, &sa)
		return
	}
	_, _ = r.conn.WriteToIP(pkt, to)
}

// replyAddr is where the server sends answers. Normally that's the packet source,
// but when the client spoofs its source the real return IP is configured (fixedPeer).
func (r *Raw) replyAddr(addr *net.IPAddr) *net.IPAddr {
	if r.fixedPeer != nil {
		return &net.IPAddr{IP: r.fixedPeer}
	}
	return addr
}

// buildIP4 assembles an IPv4 header (with a computed checksum) in front of payload.
func buildIP4(src, dst net.IP, proto int, payload []byte) []byte {
	h := make([]byte, 20+len(payload))
	h[0] = 0x45 // version 4, IHL 5 (no options)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))
	h[8] = 64 // TTL
	h[9] = byte(proto)
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	binary.BigEndian.PutUint16(h[10:12], onesComplementSum(h[:20])) // checksum field is 0 during the sum
	copy(h[20:], payload)
	return h
}

// tunToNet reads L3 packets from TUN, seals+wraps them, and sends to the peer.
func (r *Raw) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := r.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := r.peer.Load()
		if peer == nil {
			continue // server has not learned the client yet
		}
		if r.cryptoOn && r.sealer() == nil {
			continue // handshake not finished yet; drop (L4 retransmits)
		}
		body, err := r.body(typeData, buf[:n])
		if err != nil {
			log.Printf("raw: seal error: %v", err)
			continue
		}
		r.writeOut(r.wire(body, peer.IP), peer)
	}
}

// netToTun receives raw packets, strips the profile header, authenticates, and
// writes data frames into the TUN. Packets that do not open as data are tried as
// handshake messages.
func (r *Raw) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := r.conn.ReadFromIP(buf)
		if err != nil {
			return err
		}
		if r.fixedPeer == nil { // spoofing client forges its source, so we can't filter by it — the AEAD authenticates
			if peer := r.peer.Load(); peer != nil && !addr.IP.Equal(peer.IP) {
				continue // only the peer's packets are ours (raw sockets see all)
			}
		}
		body, ok := rawDecap(r.profile, buf[:n])
		if !ok {
			continue
		}
		if r.cryptoOn {
			r.handleCrypto(body, addr)
			continue
		}
		if len(body) < 2 || body[0] != magic {
			continue
		}
		r.learnPeer(addr)
		r.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
	}
}

func (r *Raw) handleCrypto(body []byte, addr *net.IPAddr) {
	if s := r.sealer(); s != nil {
		var (
			typ          byte
			session, seq uint64
			payload      []byte
			oerr         error
		)
		if r.obfs {
			typ, session, seq, payload, oerr = obfsOpen(s, body)
		} else if len(body) >= 2 && body[0] == magic {
			typ = body[1]
			session, seq, payload, oerr = s.Open(body[2:], []byte{typ})
		} else {
			oerr = errBadFrame
		}
		if oerr == nil && r.rp.ok(session, seq) {
			r.learnPeer(addr)
			r.dispatch(typ, payload, addr)
			return
		}
	}
	r.tryHandshake(body, addr)
}

// learnPeer records the peer address (and, on the server, the local source IP
// toward it, needed for the tcp profile's checksum) once a frame authenticates.
func (r *Raw) learnPeer(addr *net.IPAddr) {
	if r.fixedPeer == nil { // with a spoofing client the source is forged — keep the configured peer
		r.peer.Store(addr)
	}
	if r.localIP.Load() == nil {
		if lip := routeLocalIP(addr.IP); lip != nil {
			r.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
}

func (r *Raw) tryHandshake(body []byte, addr *net.IPAddr) {
	if r.isClient {
		ci := r.ci.Load()
		if ci == nil {
			return
		}
		eResp, err := crypto.ParseResp(r.psk, ci.Pub, body)
		if err != nil {
			return
		}
		s, err := crypto.SessionSealer(r.cipher, r.psk, ci, eResp, ci.Pub, eResp, true)
		if err != nil {
			return
		}
		r.rp = replayGuard{}
		r.session.Store(&sealerBox{s: s})
		return
	}
	eInit, err := crypto.ParseInit(r.psk, body)
	if err != nil {
		return
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	s, err := crypto.SessionSealer(r.cipher, r.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return
	}
	r.rp = replayGuard{}
	r.session.Store(&sealerBox{s: s})
	// Reply to the init source but do NOT rebind here — rebinding waits for a
	// frame that opens under the new session (learnPeer), so a replayed init
	// cannot redirect traffic.
	if r.localIP.Load() == nil {
		if lip := routeLocalIP(addr.IP); lip != nil {
			r.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	if msg2 := crypto.RespMsg(r.psk, eInit, sr); msg2 != nil {
		to := r.replyAddr(addr)
		r.writeOut(r.wire(msg2, to.IP), to)
	}
}

func (r *Raw) dispatch(typ byte, payload []byte, addr *net.IPAddr) {
	switch typ {
	case typePing:
		r.send(typePong, nil, r.replyAddr(addr))
	case typePong:
		// keepalive ack
	case typeData:
		if _, err := r.dev.Write(payload); err != nil {
			log.Printf("raw: tun write error: %v", err)
		}
	}
}

func (r *Raw) clientLoop() {
	for {
		if r.cryptoOn && r.sealer() == nil {
			r.sendInit()
		} else {
			r.send(typePing, nil, r.peer.Load())
		}
		wait := jitter(r.keepalive)
		if r.cryptoOn && r.sealer() == nil {
			wait = time.Second // retransmit the handshake faster than keepalive
		}
		select {
		case <-r.closeCh:
			return
		case <-time.After(wait):
		}
	}
}

func (r *Raw) sendInit() {
	peer := r.peer.Load()
	if peer == nil {
		return
	}
	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	r.ci.Store(ci)
	r.writeOut(r.wire(crypto.InitMsg(r.psk, ci), peer.IP), peer)
}

func (r *Raw) send(typ byte, payload []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	if r.cryptoOn && r.sealer() == nil {
		return
	}
	body, err := r.body(typ, payload)
	if err != nil {
		return
	}
	r.writeOut(r.wire(body, to.IP), to)
}

// hostOnly returns the host part of an "ip:port", or s unchanged if it has none.
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.TrimSpace(s)
}

func parseIP4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// routeLocalIP asks the kernel which local IPv4 it would use to reach peer, by
// opening (but not sending on) a connected UDP socket. Returns nil on failure.
func routeLocalIP(peer net.IP) net.IP {
	c, err := net.Dial("udp4", net.JoinHostPort(peer.String(), "9"))
	if err != nil {
		return nil
	}
	defer c.Close()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return la.IP.To4()
	}
	return nil
}
