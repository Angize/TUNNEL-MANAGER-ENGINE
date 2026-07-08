//go:build linux

// flux transport: the same sealed core frames as the other carriers, but the raw
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
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"os/exec"
	"strconv"
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

	carrier     string // "raw" (rotate IP protocol) | "udp" (proto 17, rotate ports) | "stun" (udp + STUN header, WebRTC-shaped)
	shapeProf   string // statistical shape profile: "quic" | "video" | "webrtc" | "random"
	epochOffset int64  // manual epoch bump ("rotate now"): epoch = clock-epoch + offset (both ends set identically)

	fecEnc *fecEncoder                // non-nil when FEC is on: buffers data frames into RS blocks on send
	fecDec *fecDecoder                // non-nil when FEC is on: reassembles + reconstructs blocks on receive
	rxSrc  atomic.Pointer[net.IPAddr] // src of the packet currently feeding fecDec (deliver reads it)

	sendFd int // AF_INET SOCK_RAW + IP_HDRINCL: builds each packet's IPv4 header (any protocol)
	pktFd  int // AF_PACKET SOCK_DGRAM: receives every IPv4 frame regardless of protocol

	localIP  atomic.Pointer[net.IPAddr] // our source IP toward the peer
	peer     atomic.Pointer[net.IPAddr] // current known peer (server learns it)
	session  atomic.Pointer[sealerBox]
	curShape atomic.Pointer[fluxShape] // this epoch's shape (refreshed each second by rotateWatcher)
	rp       replayGuard
	pend     *sealerBox // server: session staged by a recent init, promoted only once a frame opens under it
	pendRp   replayGuard
	hsCache  initCache // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci       atomic.Pointer[crypto.Ephemeral]
	lastRx   atomic.Int64 // unix-nano of the last authenticated frame (client staleness)
	logEp    atomic.Int64 // last epoch whose rotation was logged (rotation visibility)

	antiLeak  atomic.Pointer[func()] // anti-ICMP cleanup, written from the receive goroutine, read in Close -> atomic
	leakOnce  sync.Once              // installs antiLeak exactly once (the server learns the peer late)
	sendMu    sync.RWMutex           // senders RLock around the raw-fd Sendto; Close takes the write lock before closing it
	sendDown  bool                   // set under sendMu.Lock in Close: no more Sendto on the (about-to-be-closed) raw fd
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newFlux(dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int, isClient bool) *Flux {
	if carrier == "" {
		carrier = "udp"
	}
	if shape == "" {
		shape = "random"
	}
	f := &Flux{
		dev: dev, keepalive: ka, rotate: rotate, obfs: obfs, cryptoOn: cryptoOn,
		psk: psk, cipher: cipher, carrier: carrier, shapeProf: shape, epochOffset: epochOffset,
		isClient: isClient, sendFd: -1, pktFd: -1, closeCh: make(chan struct{}),
	}
	sh := deriveFluxShape(psk, f.epochNow(), shape)
	f.curShape.Store(&sh)
	// emit sends each ready FEC packet (data/parity shard) to the current peer wrapped
	// in the carrier; deliver feeds each recovered frame back into the normal crypto
	// path with the source of the packet that completed the block.
	f.fecEnc, f.fecDec = newFecPair(fec, fecData, fecParity, "flux",
		func(pkt []byte) {
			if p := f.peer.Load(); p != nil {
				f.carrierOut(pkt, p)
			}
		},
		func(frame []byte) {
			if s := f.rxSrc.Load(); s != nil {
				f.handleCrypto(frame, s)
			}
		})
	return f
}

// epochNow is the current shape epoch: the clock-derived epoch plus any manual
// offset. Both ends carry the same offset (set from config on a "rotate now"), so
// bumping it advances the moving target fleet-wide with no wire signal.
func (f *Flux) epochNow() int64 { return fluxEpochAt(f.rotate, time.Now()) + f.epochOffset }

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
func DialFlux(peerIP string, dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int) (*Flux, error) {
	ip := parseIP4(hostOnly(peerIP))
	if ip == nil {
		return nil, errBadFrame
	}
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, ka, rotate, obfs, cryptoOn, psk, cipher, carrier, shape, epochOffset, fec, fecData, fecParity, true)
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
func ListenFlux(listenIP string, dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int) (*Flux, error) {
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, ka, rotate, obfs, cryptoOn, psk, cipher, carrier, shape, epochOffset, fec, fecData, fecParity, false)
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

// Close tears down the sockets, the client loop, and any kernel anti-ICMP rule installed for
// the peer. Closing the fd does NOT wake a thread blocked in the AF_PACKET recvfrom, so the
// receive loop exits on its next SO_RCVTIMEO tick (<=1s) via its closeCh check, not instantly.
func (f *Flux) Close() error {
	f.closeOnce.Do(func() { close(f.closeCh) })
	if f.fecEnc != nil {
		f.fecEnc.Close() // stop the FEC flush timer before the raw fd is closed (else a late Sendto hits a reused fd)
	}
	if p := f.antiLeak.Load(); p != nil && *p != nil {
		(*p)()
	}
	// Block new sends and wait for any in-flight Sendto to finish BEFORE closing the raw fd,
	// so a sibling goroutine (clientLoop / rotateWatcher / FEC emit) can't Sendto on a closed
	// fd number that has since been reused by another socket.
	f.sendMu.Lock()
	f.sendDown = true
	f.sendMu.Unlock()
	if f.sendFd >= 0 {
		syscall.Close(f.sendFd)
	}
	if f.pktFd >= 0 {
		syscall.Close(f.pktFd)
	}
	return nil
}

// installAntiLeak drops just THIS carrier's inbound frames from the peer in the raw
// PREROUTING chain, so the kernel does not answer our exotic protocol / unbound UDP
// port with an ICMP unreachable. AF_PACKET taps every frame before that chain runs,
// so flux still receives everything. The rules are scoped to the carrier's own
// protocol/ports (NOT all traffic from the peer) so a co-located tunnel to the same
// peer — e.g. a raw/bip link on proto 253 — is not collaterally dropped. Best-effort,
// installed exactly once (the server learns the peer late).
func (f *Flux) installAntiLeak(peer net.IP) {
	f.leakOnce.Do(func() { fn := addFluxDrop(peer, f.carrier); f.antiLeak.Store(&fn) })
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

// fluxPadMax picks the padding budget for a frame. Control frames (keepalives) are
// the fingerprintable fixed-size packets, so their budget follows the shape profile
// (curShape.ctrlPad) to blend into the mimicked traffic's small-packet histogram.
// Data frames keep the standard budget so the node's MTU reservation still holds.
func (f *Flux) fluxPadMax(typ byte) int {
	if typ == typeData {
		return obfsDataPadMax
	}
	if sh := f.curShape.Load(); sh != nil {
		return sh.ctrlPad
	}
	return obfsCtrlPadMax
}

// body builds the framed (magic/type/sealed or obfs) bytes — identical to the UDP
// and raw carriers — before the IPv4 header is prepended.
func (f *Flux) body(typ byte, payload []byte) ([]byte, error) {
	s := f.sealer()
	if f.obfs {
		return obfsSeal(s, typ, payload, f.fluxPadMax(typ))
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

// carrierOut builds the full IPv4 packet in this epoch's shape around body and sends
// it to the peer via the IP_HDRINCL socket. The header source is our real IP and
// the destination is the real peer — flux rotates the carrier, it does not forge
// addresses. The "raw" carrier stamps the epoch's rotating IP protocol; the "udp"
// carrier stamps protocol 17 and wraps the frame in a UDP header whose ports rotate.
// When FEC is on, body already carries the 1-byte FEC type tag (data/parity/pass).
func (f *Flux) carrierOut(body []byte, to *net.IPAddr) {
	if to == nil || f.sendFd < 0 {
		return
	}
	sh := f.curShape.Load()
	src := f.srcIP()
	var out []byte
	switch f.carrier {
	case "raw":
		out = buildIP4(src, to.IP, sh.proto, body)
	case "stun":
		// UDP to a STUN port, payload wrapped in a real STUN Binding header so the
		// flow parses as WebRTC signalling rather than generic high-entropy UDP.
		out = buildIP4(src, to.IP, protoUDP, buildUDPSeg(src, to.IP, sh.sport, sh.dportSTUN, buildSTUN(body)))
	default: // "udp"
		out = buildIP4(src, to.IP, protoUDP, buildUDPSeg(src, to.IP, sh.sport, sh.dport, body))
	}
	if out == nil {
		return // buildIP4 refused an oversize packet (16-bit IPv4 length); not reachable under normal MTUs
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	// Guard the bare-fd Sendto: an RLock lets Close() (write lock) wait for in-flight sends
	// and then flip sendDown before syscall.Close, so we never Sendto on a closed/reused fd.
	// The RLock is uncontended in steady state and cheap next to the syscall itself.
	f.sendMu.RLock()
	if !f.sendDown {
		_ = syscall.Sendto(f.sendFd, out, 0, &sa)
	}
	f.sendMu.RUnlock()
}

// stunMagic is the STUN magic cookie (RFC 5389) at bytes 4..8 of every STUN message.
const stunMagic = 0x2112A442

// stunAttrType is the STUN attribute we stash the tunnel payload in. 0x8022 is
// SOFTWARE (RFC 5389): a comprehension-OPTIONAL attribute (top bit set) that a STUN
// parser is required to skip when it can't use it — so a DPI that walks the attribute
// stream sees a well-formed, ignorable attribute rather than opaque trailing bytes.
const stunAttrType = 0x8022

// buildSTUN wraps payload in a STUN Binding request so the carrier parses as WebRTC.
// The payload is carried as ONE STUN attribute — [type:2][len:2][value][pad to a
// 4-byte boundary] — and the STUN message-length counts the padded attribute, so it
// is a multiple of 4 exactly as a real STUN attribute stream is. Without this a
// parser that walks attributes (they must be 4-byte aligned) could tell our opaque
// ciphertext apart from genuine STUN. Fields: type 0x0001 (Binding Request, high two
// bits zero as STUN requires), the magic cookie, and a random 96-bit transaction id
// (indistinguishable from a real one — it is meant to look random).
func buildSTUN(payload []byte) []byte {
	valLen := len(payload)
	padded := (valLen + 3) &^ 3 // round the attribute value up to a 4-byte boundary
	msgLen := 4 + padded        // 4-byte attribute header + padded value
	h := make([]byte, 20+msgLen)
	binary.BigEndian.PutUint16(h[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(h[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(h[4:8], stunMagic)
	_, _ = rand.Read(h[8:20]) // transaction id
	binary.BigEndian.PutUint16(h[20:22], stunAttrType)
	binary.BigEndian.PutUint16(h[22:24], uint16(valLen)) // attribute length excludes the pad
	copy(h[24:], payload)
	// h[24+valLen : 24+padded] stays zero — the attribute's alignment padding.
	return h
}

// parseSTUN strips the 20-byte STUN header AND the 4-byte attribute header, returning
// exactly the attribute value (ignoring the 4-byte-boundary pad). It requires the
// magic cookie so a stray non-STUN datagram on the port is rejected before the AEAD.
func parseSTUN(pkt []byte) ([]byte, bool) {
	if len(pkt) < 24 || binary.BigEndian.Uint32(pkt[4:8]) != stunMagic {
		return nil, false
	}
	valLen := int(binary.BigEndian.Uint16(pkt[22:24])) // attribute length = real payload size (no pad)
	if 24+valLen > len(pkt) {
		return nil, false
	}
	return pkt[24 : 24+valLen], true
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

// fluxDropMatches returns the iptables match fragments (one per rule) that select
// exactly this carrier's inbound traffic from peer — scoped to the carrier's own
// protocol/ports so it never drops another tunnel's packets to the same peer:
//   - raw:  one rule per experimental protocol in the pool (-p <proto>)
//   - stun: one rule per STUN destination port (-p udp --dport <p>)
//   - udp:  one rule per QUIC/STUN/WebRTC destination port (-p udp --dport <p>)
func fluxDropMatches(peer net.IP, carrier string) [][]string {
	s := peer.String()
	var out [][]string
	switch carrier {
	case "raw":
		for _, p := range fluxProtoPool {
			out = append(out, []string{"-s", s, "-p", strconv.Itoa(p)})
		}
	case "stun":
		for _, dp := range fluxStunDports {
			out = append(out, []string{"-s", s, "-p", "udp", "--dport", strconv.Itoa(int(dp))})
		}
	default: // udp
		for _, dp := range fluxDportPool {
			out = append(out, []string{"-s", s, "-p", "udp", "--dport", strconv.Itoa(int(dp))})
		}
	}
	return out
}

// addFluxDrop installs best-effort raw-PREROUTING DROP rules for exactly this
// carrier's traffic from peer, so the kernel never ICMP-rejects our frames while a
// co-located tunnel (e.g. raw/bip on proto 253) to the same peer keeps working.
// AF_PACKET taps before this chain, so flux's receive is unaffected. Returns a
// cleanup func that removes every rule it managed to install (nil if none).
func addFluxDrop(peer net.IP, carrier string) func() {
	var added [][]string
	for _, m := range fluxDropMatches(peer, carrier) {
		args := append([]string{"-t", "raw", "-A", "PREROUTING"}, append(append([]string{}, m...), "-j", "DROP")...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			log.Printf("flux: anti-leak rule not installed (kernel may ICMP-reject our carrier): %v: %s", err, strings.TrimSpace(string(out)))
			continue
		}
		added = append(added, m)
	}
	if len(added) == 0 {
		return nil
	}
	return func() {
		for _, m := range added {
			del := append([]string{"-t", "raw", "-D", "PREROUTING"}, append(append([]string{}, m...), "-j", "DROP")...)
			_ = exec.Command("iptables", del...).Run()
		}
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
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue // EAGAIN: the SO_RCVTIMEO tick fired (lets Close be noticed); EINTR: a signal
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
		if e := f.epochNow(); e != graceEpoch {
			graceP = graceProtos(f.psk, e, f.shapeProf)
			graceD = graceDports(f.psk, e, f.shapeProf, f.carrier)
			graceEpoch = e
		}
		var body []byte
		if f.carrier == "raw" {
			if !graceP[int(pkt[9])] {
				continue // not a flux carrier protocol for any live epoch
			}
			body = pkt[ihl:]
		} else { // udp or stun carrier — both ride protocol 17
			if int(pkt[9]) != protoUDP || len(pkt) < ihl+8 {
				continue
			}
			if !graceD[binary.BigEndian.Uint16(pkt[ihl+2:ihl+4])] {
				continue // not a flux carrier destination port for any live epoch
			}
			body = pkt[ihl+8:] // strip the UDP header
			if f.carrier == "stun" {
				inner, ok := parseSTUN(body)
				if !ok {
					continue // not a STUN datagram
				}
				body = inner
			}
		}
		src := &net.IPAddr{IP: append(net.IP(nil), pkt[12:16]...)}
		if peer := f.peer.Load(); peer != nil && !src.IP.Equal(peer.IP) {
			continue // only the peer's frames are ours (AF_PACKET sees all hosts)
		}
		if f.fecDec != nil {
			// netToTun is the sole reader, so rxSrc is stable for the whole input()
			// call (the decoder delivers recovered frames synchronously within it).
			f.rxSrc.Store(src)
			f.fecDec.input(body)
		} else {
			f.handleCrypto(body, src)
		}
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
		if f.fecEnc != nil {
			f.fecEnc.addData(body) // buffered into an RS block; shards go out via the emit callback
		} else {
			f.carrierOut(body, peer)
		}
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
		if typ, session, seq, payload, oerr := f.openWith(s, body); oerr == nil && f.rp.ok(session, seq) {
			f.lastRx.Store(time.Now().UnixNano())
			f.learnPeer(addr)
			f.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a PENDING session
	// staged by a recent init; promote it only when a frame actually opens under it, so a
	// replayed init cannot tear down the live session or its replay window.
	if f.pend != nil {
		if typ, session, seq, payload, oerr := f.openWith(f.pend.s, body); oerr == nil && f.pendRp.ok(session, seq) {
			f.session.Store(f.pend)
			f.rp = f.pendRp
			f.pend = nil
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

// openWith tries to open one datagram under a specific session sealer, touching no
// session/replay state so a frame can be tried against both the live and a pending session.
func (f *Flux) openWith(s Sealer, body []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	if f.obfs {
		return obfsOpen(s, body)
	}
	if len(body) >= 2 && body[0] == magic {
		typ = body[1]
		session, seq, payload, oerr = s.Open(body[2:], []byte{typ})
		return
	}
	return 0, 0, 0, nil, errBadFrame
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
	// Compute-DoS mitigation: an attacker replaying captured valid inits at high rate
	// would otherwise force a fresh ECDH+HKDF (GenerateEphemeral+SessionSealer) per packet.
	// If this init matches one we recently answered (while a pending session is current),
	// re-send the already-computed response and return before that expensive crypto. The
	// handshake outcome is unchanged (pend/promote-on-open is untouched); a genuinely new
	// init falls through to the full handshake below. The cache is a small LRU (not a
	// single entry) so alternating two captured inits cannot bust it. It is touched only on
	// this single receive goroutine (like pend/rp), so no locking is needed.
	if f.pend != nil {
		if resp, ok := f.hsCache.get(body); ok {
			f.sendCtrl(resp, addr)
			return
		}
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
	// Stage the new session as PENDING; the live session and its replay window survive until
	// a frame actually opens under these new keys (see handleCrypto), so a replayed init
	// cannot wedge the tunnel. Peer rebinding is likewise deferred to that first frame.
	f.pend = &sealerBox{s: s}
	f.pendRp = replayGuard{}
	if f.localIP.Load() == nil {
		if lip := routeLocalIP(addr.IP); lip != nil {
			f.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	if msg2 := crypto.RespMsg(f.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while pend is
		// still current) is served without recomputing the crypto above. put copies body
		// (it aliases the receive buffer); msg2 is a fresh slice, safe to keep.
		f.hsCache.put(body, msg2)
		f.sendCtrl(msg2, addr)
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
	// Reuse the current ephemeral across retransmits — regenerate only for a fresh handshake
	// cycle (ci==nil). Regenerating each 1s retransmit races the reply on high-RTT links: the
	// resp (verified against the current ci) would always check against a newer ephemeral and
	// be dropped, so the handshake could never complete on exactly the throttled links we target.
	ci := f.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		f.ci.Store(ci)
	}
	f.sendCtrl(crypto.InitMsg(f.psk, ci), peer)
}

// sendCtrl sends a control/handshake frame. Under FEC it is tagged passthrough so
// the peer's decoder forwards it straight through instead of parsing it as a shard
// (or holding it in a block). `to` may differ from the learned peer — e.g. a
// server's handshake reply to the init's source before the peer is committed.
func (f *Flux) sendCtrl(body []byte, to *net.IPAddr) {
	f.carrierOut(fecTag(f.fecEnc, body), to)
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
	f.sendCtrl(body, to)
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
			sh := deriveFluxShape(f.psk, f.epochNow(), f.shapeProf)
			f.curShape.Store(&sh)
			if prev := f.logEp.Swap(sh.epoch); prev != sh.epoch && prev != 0 {
				switch f.carrier {
				case "raw":
					log.Printf("flux: rotated to epoch %d (raw carrier proto %d)", sh.epoch, sh.proto)
				case "stun":
					log.Printf("flux: rotated to epoch %d (stun carrier :%d)", sh.epoch, sh.dportSTUN)
				default:
					log.Printf("flux: rotated to epoch %d (udp carrier :%d)", sh.epoch, sh.dport)
				}
			}
		}
	}
}
