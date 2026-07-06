//go:build linux

// flux transport: the same sealed bip frames as the other carriers, but the raw
// IPv4 carrier PROTOCOL rotates every epoch on a schedule both ends derive from
// the wall clock (see flux.go) — a signal-free moving target. Because the
// protocol moves, flux cannot bind a fixed-protocol socket the way the raw
// profiles do: it SENDS through one IP_HDRINCL socket (which lets us stamp any
// protocol number per packet) and RECEIVES through an AF_PACKET socket (which
// sees every protocol), accepting the small grace-window set of protocols the
// current/adjacent epochs derive and then authenticating with the AEAD.
//
// Session establishment (ephemeral X25519 handshake), replay guard, obfs framing
// and clear/crypto modes are identical to the raw carrier — only the socket plumbing
// and the per-epoch protocol differ. The session sealer is independent of the epoch,
// so a rotation changes how packets LOOK without touching how they OPEN: no
// re-handshake is needed when the shape rotates.
package packet

import (
	"encoding/binary"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// Flux carries L3 packets between a TUN device and a peer over a raw IPv4 carrier
// whose protocol number rotates every epoch.
type Flux struct {
	dev       *tun.Device
	keepalive time.Duration
	rotate    time.Duration
	obfs      bool
	cryptoOn  bool
	psk       string
	cipher    string
	isClient  bool

	carrier string // "raw" (rotate IP protocol) or "udp" (proto 17, rotate ports) — internet-safe

	sendFd int // AF_INET SOCK_RAW + IP_HDRINCL: builds each packet's IPv4 header (any protocol)
	pktFd  int // AF_PACKET SOCK_DGRAM: receives every IPv4 frame regardless of protocol

	localIP  atomic.Pointer[net.IPAddr] // our source IP toward the peer
	peer     atomic.Pointer[net.IPAddr] // current known peer (server learns it)
	session  atomic.Pointer[sealerBox]
	curShape atomic.Pointer[fluxShape] // this epoch's shape (refreshed each second by rotateWatcher)
	rp       replayGuard
	ci       atomic.Pointer[crypto.Ephemeral]
	lastRx   atomic.Int64 // unix-nano of the last authenticated frame (client staleness)
	logEp    atomic.Int64 // last epoch whose rotation was logged (rotation visibility)

	antiLeak  func()    // removes the kernel anti-ICMP (iptables) rule for the peer on Close
	leakOnce  sync.Once // installs antiLeak exactly once (the server learns the peer late)
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newFlux(dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier string, isClient bool) *Flux {
	if carrier == "" {
		carrier = "udp"
	}
	f := &Flux{
		dev: dev, keepalive: ka, rotate: rotate, obfs: obfs, cryptoOn: cryptoOn,
		psk: psk, cipher: cipher, carrier: carrier, isClient: isClient, sendFd: -1, pktFd: -1,
		closeCh: make(chan struct{}),
	}
	sh := deriveFluxShape(psk, fluxEpochAt(rotate, time.Now()))
	f.curShape.Store(&sh)
	return f
}

// openFluxSockets opens the shared IP_HDRINCL sender and AF_PACKET receiver. The
// sender is created for bip's protocol number, but IP_HDRINCL means the protocol
// we stamp in each packet's header is what actually goes on the wire, so one
// socket serves every epoch's protocol.
func openFluxSockets() (send, pkt int, err error) {
	send, err = openHdrincl(protoBIP)
	if err != nil {
		return -1, -1, err
	}
	pkt, err = openAfpacket()
	if err != nil {
		syscall.Close(send)
		return -1, -1, err
	}
	return send, pkt, nil
}

// DialFlux (client role) targets peerIP. peerIP may be a plain IPv4 or "ip:port"
// (the port is ignored — the raw carrier has no ports of its own).
func DialFlux(peerIP string, dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier string) (*Flux, error) {
	ip := parseIP4(hostOnly(peerIP))
	if ip == nil {
		return nil, errBadFrame
	}
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, ka, rotate, obfs, cryptoOn, psk, cipher, carrier, true)
	f.sendFd, f.pktFd = send, pkt
	f.peer.Store(&net.IPAddr{IP: ip})
	if lip := routeLocalIP(ip); lip != nil {
		f.localIP.Store(&net.IPAddr{IP: lip})
	}
	f.installAntiLeak(ip) // the peer is known up front — suppress kernel ICMP for its frames now
	return f, nil
}

// ListenFlux (server role) waits to learn the peer from the first authenticated
// frame. listenIP is accepted for signature parity with the other carriers but is
// not used: AF_PACKET receives on every interface and the source filter is the peer.
func ListenFlux(listenIP string, dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier string) (*Flux, error) {
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, ka, rotate, obfs, cryptoOn, psk, cipher, carrier, false)
	f.sendFd, f.pktFd = send, pkt
	return f, nil
}

// Run blocks until a loop fails (a socket or the device closes).
func (f *Flux) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- f.tunToNet() }()
	go func() { errc <- f.netToTun() }()
	go f.rotateWatcher()
	if f.isClient {
		go f.clientLoop()
	}
	return <-errc
}

// Close tears down the sockets (unblocking the loops), the client loop, and any
// kernel anti-ICMP rule installed for the peer.
func (f *Flux) Close() error {
	f.closeOnce.Do(func() { close(f.closeCh) })
	if f.antiLeak != nil {
		f.antiLeak()
	}
	if f.sendFd >= 0 {
		syscall.Close(f.sendFd)
	}
	if f.pktFd >= 0 {
		syscall.Close(f.pktFd)
	}
	return nil
}

// installAntiLeak drops the peer's frames in the raw PREROUTING chain so the kernel
// does not answer our exotic protocol / unbound UDP port with an ICMP unreachable.
// AF_PACKET taps every frame before that chain runs, so flux still receives everything.
// Best-effort and installed exactly once (the server learns the peer late).
func (f *Flux) installAntiLeak(peer net.IP) {
	f.leakOnce.Do(func() { f.antiLeak = addPeerDrop(peer) })
}

func (f *Flux) sealer() Sealer {
	if box := f.session.Load(); box != nil {
		return box.s
	}
	return nil
}

func (f *Flux) srcIP() net.IP {
	if l := f.localIP.Load(); l != nil {
		return l.IP
	}
	return net.IPv4zero
}

// body builds the framed (magic/type/sealed or obfs) bytes — identical to the UDP
// and raw carriers — before the IPv4 header is prepended.
func (f *Flux) body(typ byte, payload []byte) ([]byte, error) {
	s := f.sealer()
	if f.obfs {
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

// writeOut builds the full IPv4 packet in this epoch's shape around body and sends
// it to the peer via the IP_HDRINCL socket. The header source is our real IP and
// the destination is the real peer — flux rotates the carrier, it does not forge
// addresses. The "raw" carrier stamps the epoch's rotating IP protocol; the "udp"
// carrier stamps protocol 17 and wraps the frame in a UDP header whose ports rotate.
func (f *Flux) writeOut(body []byte, to *net.IPAddr) {
	if to == nil || f.sendFd < 0 {
		return
	}
	sh := f.curShape.Load()
	src := f.srcIP()
	var out []byte
	if f.carrier == "raw" {
		out = buildIP4(src, to.IP, sh.proto, body)
	} else {
		out = buildIP4(src, to.IP, protoUDP, buildUDPSeg(src, to.IP, sh.sport, sh.dport, body))
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	_ = syscall.Sendto(f.sendFd, out, 0, &sa)
}

// buildUDPSeg wraps payload in a UDP header with the given ports and a correct
// checksum (over the IPv4 pseudo-header), so the udp carrier's packets are valid
// UDP datagrams any transit will forward.
func buildUDPSeg(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], uint16(len(h)))
	copy(h[8:], payload)
	cs := l4Checksum(src, dst, protoUDP, h)
	if cs == 0 {
		cs = 0xffff // 0 means "no checksum" in UDP; use the equivalent 0xffff
	}
	binary.BigEndian.PutUint16(h[6:8], cs)
	return h
}

// addPeerDrop installs a best-effort iptables rule dropping all frames from peer in
// the raw table's PREROUTING chain, so the kernel never answers our carrier with an
// ICMP unreachable. AF_PACKET taps before this chain, so flux's receive is unaffected.
// Returns a cleanup func (nil if the rule could not be installed).
func addPeerDrop(peer net.IP) func() {
	args := []string{"-t", "raw", "-A", "PREROUTING", "-s", peer.String(), "-j", "DROP"}
	if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
		log.Printf("flux: anti-leak rule not installed (kernel may ICMP-reject our carrier): %v: %s", err, strings.TrimSpace(string(out)))
		return nil
	}
	return func() {
		del := append([]string(nil), args...)
		del[2] = "-D"
		_ = exec.Command("iptables", del...).Run()
	}
}

// netToTun receives every IPv4 frame via AF_PACKET, keeps those that match the
// current carrier's grace window (raw: IP protocol ∈ prev/current/next epoch; udp:
// protocol 17 with a destination port ∈ the epochs' ports) and — once the peer is
// known — whose source is the peer, strips the carrier header, then authenticates
// and dispatches. SOCK_DGRAM strips the link header, so each frame starts at the IPv4 header.
func (f *Flux) netToTun() error {
	buf := make([]byte, maxDatagram+64)
	var graceEpoch int64 = -1
	var graceP map[int]bool
	var graceD map[uint16]bool
	for {
		n, from, err := syscall.Recvfrom(f.pktFd, buf, 0)
		if err != nil {
			select {
			case <-f.closeCh:
				return nil
			default:
			}
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == packetOutgoing {
			continue // ignore frames we transmitted ourselves
		}
		pkt := buf[:n]
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			continue // not IPv4
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			continue
		}
		if e := fluxEpochAt(f.rotate, time.Now()); e != graceEpoch {
			graceP = graceProtos(f.psk, f.rotate, time.Now())
			graceD = graceDports(f.psk, f.rotate, time.Now())
			graceEpoch = e
		}
		var body []byte
		if f.carrier == "raw" {
			if !graceP[int(pkt[9])] {
				continue // not a flux carrier protocol for any live epoch
			}
			body = pkt[ihl:]
		} else { // udp carrier
			if int(pkt[9]) != protoUDP || len(pkt) < ihl+8 {
				continue
			}
			if !graceD[binary.BigEndian.Uint16(pkt[ihl+2:ihl+4])] {
				continue // not a flux carrier destination port for any live epoch
			}
			body = pkt[ihl+8:] // strip the UDP header
		}
		src := &net.IPAddr{IP: append(net.IP(nil), pkt[12:16]...)}
		if peer := f.peer.Load(); peer != nil && !src.IP.Equal(peer.IP) {
			continue // only the peer's frames are ours (AF_PACKET sees all hosts)
		}
		f.handleCrypto(body, src)
	}
}

// tunToNet reads L3 packets from TUN, seals them, and sends to the peer.
func (f *Flux) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := f.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := f.peer.Load()
		if peer == nil {
			continue // server has not learned the client yet
		}
		if f.cryptoOn && f.sealer() == nil {
			continue // handshake not finished yet; drop (L4 retransmits)
		}
		body, err := f.body(typeData, buf[:n])
		if err != nil {
			log.Printf("flux: seal error: %v", err)
			continue
		}
		f.writeOut(body, peer)
	}
}

func (f *Flux) handleCrypto(body []byte, addr *net.IPAddr) {
	if !f.cryptoOn {
		if len(body) < 2 || body[0] != magic {
			return
		}
		f.learnPeer(addr)
		f.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
		return
	}
	if s := f.sealer(); s != nil {
		var (
			typ          byte
			session, seq uint64
			payload      []byte
			oerr         error
		)
		if f.obfs {
			typ, session, seq, payload, oerr = obfsOpen(s, body)
		} else if len(body) >= 2 && body[0] == magic {
			typ = body[1]
			session, seq, payload, oerr = s.Open(body[2:], []byte{typ})
		} else {
			oerr = errBadFrame
		}
		if oerr == nil && f.rp.ok(session, seq) {
			f.lastRx.Store(time.Now().UnixNano())
			f.learnPeer(addr)
			f.dispatch(typ, payload, addr)
			return
		}
	}
	f.tryHandshake(body, addr)
}

// learnPeer records the peer address (and, on the server, the local source IP
// toward it) once a frame authenticates, and installs the peer's anti-ICMP rule the
// first time (the server has no peer to scope it to until now).
func (f *Flux) learnPeer(addr *net.IPAddr) {
	f.peer.Store(addr)
	if f.localIP.Load() == nil {
		if lip := routeLocalIP(addr.IP); lip != nil {
			f.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	f.installAntiLeak(addr.IP)
}

func (f *Flux) tryHandshake(body []byte, addr *net.IPAddr) {
	if f.isClient {
		ci := f.ci.Load()
		if ci == nil {
			return
		}
		eResp, err := crypto.ParseResp(f.psk, ci.Pub, body)
		if err != nil {
			return
		}
		s, err := crypto.SessionSealer(f.cipher, f.psk, ci, eResp, ci.Pub, eResp, true)
		if err != nil {
			return
		}
		f.rp = replayGuard{}
		f.session.Store(&sealerBox{s: s})
		f.lastRx.Store(time.Now().UnixNano())
		return
	}
	eInit, err := crypto.ParseInit(f.psk, body)
	if err != nil {
		return
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	s, err := crypto.SessionSealer(f.cipher, f.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return
	}
	f.rp = replayGuard{}
	f.session.Store(&sealerBox{s: s})
	if f.localIP.Load() == nil {
		if lip := routeLocalIP(addr.IP); lip != nil {
			f.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	// Reply to the init source but do NOT rebind here — rebinding waits for a
	// frame that opens under the new session (learnPeer), so a replayed init
	// cannot redirect traffic.
	if msg2 := crypto.RespMsg(f.psk, eInit, sr); msg2 != nil {
		f.writeOut(msg2, addr)
	}
}

func (f *Flux) dispatch(typ byte, payload []byte, addr *net.IPAddr) {
	switch typ {
	case typePing:
		f.send(typePong, nil, addr)
	case typePong:
		// keepalive ack
	case typeData:
		if _, err := f.dev.Write(payload); err != nil {
			log.Printf("flux: tun write error: %v", err)
		}
	}
}

// sessionStale mirrors Raw.sessionStale: if the client has heard nothing
// authenticated for ~3×keepalive (min 10s) the server probably restarted, so the
// client drops the dead session and re-handshakes rather than pinging forever
// under a key the fresh server cannot open.
func (f *Flux) sessionStale() bool {
	last := f.lastRx.Load()
	if last == 0 {
		return false
	}
	w := 3 * f.keepalive
	if w < 10*time.Second {
		w = 10 * time.Second
	}
	return time.Since(time.Unix(0, last)) > w
}

func (f *Flux) clientLoop() {
	for {
		if f.cryptoOn && f.sealer() != nil && f.sessionStale() {
			f.session.Store(nil)
			f.ci.Store(nil)
			log.Print("flux: no reply from the peer's session — re-handshaking (peer likely restarted)")
		}
		if f.cryptoOn && f.sealer() == nil {
			f.sendInit()
		} else {
			f.send(typePing, nil, f.peer.Load())
		}
		wait := jitter(f.keepalive)
		if f.cryptoOn && f.sealer() == nil {
			wait = time.Second // retransmit the handshake faster than keepalive
		}
		select {
		case <-f.closeCh:
			return
		case <-time.After(wait):
		}
	}
}

func (f *Flux) sendInit() {
	peer := f.peer.Load()
	if peer == nil {
		return
	}
	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	f.ci.Store(ci)
	f.writeOut(crypto.InitMsg(f.psk, ci), peer)
}

func (f *Flux) send(typ byte, payload []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	if f.cryptoOn && f.sealer() == nil {
		return
	}
	body, err := f.body(typ, payload)
	if err != nil {
		return
	}
	f.writeOut(body, to)
}

// rotateWatcher refreshes the cached send-side shape every second (so writeOut
// never pays for an HKDF per packet) and logs each rotation, so an operator — and
// the netns PoC — can see the moving target change with no wire signal. It only
// observes the clock; the derivation both ends run is what keeps them in lock-step.
func (f *Flux) rotateWatcher() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-f.closeCh:
			return
		case <-t.C:
			sh := deriveFluxShape(f.psk, fluxEpochAt(f.rotate, time.Now()))
			f.curShape.Store(&sh)
			if prev := f.logEp.Swap(sh.epoch); prev != sh.epoch && prev != 0 {
				if f.carrier == "raw" {
					log.Printf("flux: rotated to epoch %d (raw carrier proto %d)", sh.epoch, sh.proto)
				} else {
					log.Printf("flux: rotated to epoch %d (udp carrier :%d)", sh.epoch, sh.dport)
				}
			}
		}
	}
}
