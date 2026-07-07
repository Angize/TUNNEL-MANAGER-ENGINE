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

	// IP spoofing. spoofFd is a SOCK_RAW+IP_HDRINCL socket used to build the whole IPv4
	// header ourselves, so any of the outer addresses can be forged:
	//   - spoofSrc: forged source (client hides its real IP; server replies AS the decoy).
	//   - spoofDst: forged destination = the decoy (client only) — routing still targets the
	//     real peer via the sendto() address, so the packet reaches the server while the wire
	//     shows the decoy as destination.
	// A decoy destination isn't a local address on the server, so the kernel would drop it
	// before an AF_INET raw socket; the server therefore RECEIVES via pktFd (AF_PACKET),
	// filtering incoming frames to decoy. fixedPeer is the client's REAL IP (the reply
	// target) — needed because the source is forged, so the server can't learn it; it also
	// pins the peer and disables the source filter (the AEAD still authenticates).
	proto     int
	spoofSrc  net.IP
	spoofDst  net.IP // client: forged header destination (decoy); server: nil
	decoy     net.IP // server: AF_PACKET receive filter (the decoy destination)
	spoofFd   int    // AF_INET SOCK_RAW + IP_HDRINCL sender (-1 if unused)
	pktFd     int    // AF_PACKET receiver for decoy-dst frames (-1 if unused)
	fixedPeer net.IP
	antiLeak  func() // removes the kernel anti-leak (iptables) rule on Close

	localIP atomic.Pointer[net.IPAddr] // our source IP toward the peer (for TCP/UDP checksums)
	peer    atomic.Pointer[net.IPAddr] // current known peer (server learns it)
	session atomic.Pointer[sealerBox]
	rp      replayGuard
	pend    *sealerBox // server: session staged by a recent init, promoted only once a frame opens under it
	pendRp  replayGuard
	hsCache initCache // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci      atomic.Pointer[crypto.Ephemeral]
	seq     atomic.Uint32
	lastRx  atomic.Int64 // unix-nano of the last authenticated frame (client staleness)

	fecEnc *fecEncoder                // non-nil when FEC is on: buffers data frames into RS blocks on send
	fecDec *fecDecoder                // non-nil when FEC is on: reassembles + reconstructs blocks on receive
	rxAddr atomic.Pointer[net.IPAddr] // src of the packet currently feeding fecDec (deliver reads it)

	sendMu   sync.RWMutex // senders RLock around the raw spoofFd Sendto; Close write-locks before closing it
	sendDown bool         // set under sendMu.Lock in Close: no more Sendto on the (about-to-be-closed) spoofFd

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newRaw(conn *net.IPConn, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, isClient bool) *Raw {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	return &Raw{
		conn: conn, dev: dev, keepalive: ka, obfs: obfs, cryptoOn: cryptoOn,
		psk: psk, cipher: cipher, profile: profile, isClient: isClient, spoofFd: -1, pktFd: -1,
		icmpID: binary.BigEndian.Uint16(idb[:]), closeCh: make(chan struct{}),
	}
}

// DialRaw (client role) opens a raw socket of the profile's protocol and targets
// peerIP. peerIP may be a plain IPv4 or an "ip:port" (the port is ignored — raw
// IP has no ports of its own; the tcp/udp profiles carry synthetic ones).
func DialRaw(peerIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile, spoofSrc, spoofDst string, fec bool, fecData, fecParity int) (*Raw, error) {
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
		r.spoofSrc = sip
	}
	if spoofDst != "" { // forge the outer destination to the decoy; routing still targets the real peer
		dip := parseIP4(hostOnly(spoofDst))
		if dip == nil {
			conn.Close()
			return nil, fmt.Errorf("raw: spoof_dst_ip %q is not an IPv4 address", spoofDst)
		}
		r.spoofDst = dip
		// The server answers AS the decoy, so replies don't come from the real peer —
		// pin the peer and skip the source filter (the AEAD authenticates).
	}
	if r.spoofSrc != nil || r.spoofDst != nil { // any forged field needs the IP_HDRINCL socket
		fd, err := openHdrincl(proto)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("raw: spoof socket: %w", err)
		}
		r.spoofFd = fd
	}
	r.initFec(fec, fecData, fecParity)
	return r, nil
}

// ListenRaw (server role) binds a raw socket of the profile's protocol and waits
// to learn the peer from the first authenticated frame. listenIP may be empty,
// "0.0.0.0", a plain IPv4, or an "ip:port" (the port is ignored).
func ListenRaw(listenIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile, spoofPeer, spoofDst string, fec bool, fecData, fecParity int) (*Raw, error) {
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
	if spoofDst != "" { // clients aim at this decoy; receive it via AF_PACKET and answer AS it
		dip := parseIP4(hostOnly(spoofDst))
		if dip == nil {
			conn.Close()
			return nil, fmt.Errorf("raw: spoof_dst_ip %q is not an IPv4 address", spoofDst)
		}
		r.decoy = dip
		r.spoofSrc = dip // replies leave with the decoy as their source
		fd, err := openHdrincl(proto)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("raw: spoof socket: %w", err)
		}
		r.spoofFd = fd
		pfd, err := openAfpacket()
		if err != nil {
			syscall.Close(fd)
			conn.Close()
			return nil, fmt.Errorf("raw: AF_PACKET socket: %w", err)
		}
		r.pktFd = pfd
		r.antiLeak = addAntiLeak(proto, dip) // best-effort; stops the kernel forwarding the decoy dst
	}
	r.initFec(fec, fecData, fecParity)
	return r, nil
}

// initFec wires the FEC encoder/decoder (no-op when fec is off). Data shards are
// profile-wrapped and emitted to the current peer; recovered frames re-enter the
// normal receive path with the source of the packet that completed their block.
func (r *Raw) initFec(fec bool, fecData, fecParity int) {
	r.fecEnc, r.fecDec = newFecPair(fec, fecData, fecParity, "raw",
		func(pkt []byte) {
			if p := r.peer.Load(); p != nil {
				r.writeOut(r.wire(pkt, p.IP), p)
			}
		},
		func(frame []byte) { r.deliver(frame, r.rxAddr.Load()) })
}

// Run blocks until one of the loops fails (e.g. the socket or device closes).
func (r *Raw) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- r.tunToNet() }()
	if r.pktFd >= 0 { // decoy server: the real dst isn't local, so read raw frames off the wire
		go func() { errc <- r.afpacketToTun() }()
	} else {
		go func() { errc <- r.netToTun() }()
	}
	if r.isClient {
		go r.clientLoop()
	}
	return <-errc
}

// Close tears down the sockets, the client loop, and any kernel anti-leak rule installed for a
// decoy destination. The AF_INET loop is woken by closing its conn; the AF_PACKET decoy loop is
// not, so it exits on the next SO_RCVTIMEO tick (<=1s) via its closeCh check.
func (r *Raw) Close() error {
	r.closeOnce.Do(func() { close(r.closeCh) })
	if r.fecEnc != nil {
		r.fecEnc.Close() // stop the FEC flush timer before the raw fd is closed (else a late Sendto hits a reused fd)
	}
	if r.antiLeak != nil {
		r.antiLeak()
	}
	// Block new sends and wait for any in-flight Sendto to finish before closing the raw
	// spoofFd, so a sibling goroutine can't Sendto on a closed fd number that was reused.
	r.sendMu.Lock()
	r.sendDown = true
	r.sendMu.Unlock()
	if r.spoofFd >= 0 {
		syscall.Close(r.spoofFd)
	}
	if r.pktFd >= 0 {
		syscall.Close(r.pktFd)
	}
	return r.conn.Close()
}

// pinnedPeer reports whether the peer address is fixed and the source filter must be
// skipped: on the server when the client forges its source (fixedPeer), and on the
// client when the server answers as the decoy (spoofDst) instead of its real IP.
func (r *Raw) pinnedPeer() bool {
	return r.fixedPeer != nil || (r.isClient && r.spoofDst != nil)
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

// writeOut sends one wrapped packet toward the real peer `to`. When any outer
// address is forged it builds the whole IPv4 header via the IP_HDRINCL socket: the
// source is spoofSrc when set (else our real IP), and the destination is the decoy
// (spoofDst) when set (else `to`). Crucially the sendto() address is ALWAYS the real
// peer, so routing reaches the server even though the header shows the decoy dst.
func (r *Raw) writeOut(pkt []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	if r.spoofFd >= 0 {
		src := r.srcIP()
		if r.spoofSrc != nil {
			src = r.spoofSrc
		}
		dst := to.IP
		if r.spoofDst != nil {
			dst = r.spoofDst
		}
		out := buildIP4(src, dst, r.proto, pkt)
		if out == nil {
			return // oversize for the IPv4 length field (not reachable under normal MTUs)
		}
		var sa syscall.SockaddrInet4
		copy(sa.Addr[:], to.IP.To4())
		// Guard the bare-fd Sendto so Close() can wait for in-flight sends and flip sendDown
		// before syscall.Close(spoofFd) — else a sibling goroutine could Sendto on a reused fd.
		// (The conn.WriteToIP path below is poller-managed and safe against a concurrent Close.)
		r.sendMu.RLock()
		if !r.sendDown {
			_ = syscall.Sendto(r.spoofFd, out, 0, &sa)
		}
		r.sendMu.RUnlock()
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
	if len(payload) > 0xffff-20 {
		return nil // the IPv4 total-length field is 16-bit; refuse rather than truncate it (MTU-bounded, so defensive)
	}
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

// packetOutgoing is PACKET_OUTGOING: AF_PACKET delivers our own transmitted frames
// too, and those are skipped so the server never processes its own decoy replies.
const packetOutgoing = 4

// ethPIP is ETH_P_IP (the IPv4 EtherType); the AF_PACKET socket is opened for it so
// only IPv4 frames are delivered.
const ethPIP = 0x0800

// htons converts a uint16 to network byte order for the AF_PACKET protocol argument.
// Deployment targets (x86-64, arm64) are little-endian, so this is a byte swap.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// ProbeSpoof checks whether the raw sockets IP spoofing needs can be opened here.
// It opens (and immediately closes) an IP_HDRINCL raw socket and an AF_PACKET socket;
// EPERM on either means the process lacks CAP_NET_RAW. bip's protocol number (253) is
// used for the raw-socket probe. This is a local check only — see SpoofProbe.
func ProbeSpoof() SpoofProbe {
	p := SpoofProbe{}
	if fd, err := openHdrincl(253); err == nil {
		p.CapNetRaw = true
		syscall.Close(fd)
	} else {
		p.Reason = "raw sockets not permitted (needs CAP_NET_RAW / root): " + err.Error()
	}
	if fd, err := openAfpacket(); err == nil {
		p.AFPacket = true
		syscall.Close(fd)
	} else if p.Reason == "" {
		p.Reason = "AF_PACKET not permitted (needs CAP_NET_RAW / root): " + err.Error()
	}
	p.OK = p.CapNetRaw && p.AFPacket
	if p.OK {
		p.Reason = ""
	}
	return p
}

// openHdrincl opens an AF_INET raw socket of proto with IP_HDRINCL set, so the caller
// supplies the whole IPv4 header (used to forge the outer source and/or destination).
func openHdrincl(proto int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// openAfpacket opens an AF_PACKET SOCK_DGRAM socket for IPv4 frames, used to receive
// packets addressed to the decoy destination (which the IP stack would otherwise drop).
func openAfpacket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(ethPIP)))
	if err != nil {
		return -1, err
	}
	// A finite receive timeout makes the AF_PACKET Recvfrom loops interruptible: on Linux,
	// closing the fd does NOT wake a thread already blocked in recvfrom(2), so without this a
	// receive goroutine parks until the next matching frame and leaks past Close(). With
	// SO_RCVTIMEO the loop wakes ~once/sec with EAGAIN and re-checks closeCh.
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// addAntiLeak installs a best-effort iptables rule that drops the decoy-destined
// packets in the raw table's PREROUTING chain, so the kernel does not try to forward
// or answer them. AF_PACKET taps the frame before this chain runs, so our receive path
// is unaffected. Returns a cleanup func (nil if the rule could not be installed).
func addAntiLeak(proto int, decoy net.IP) func() {
	args := []string{"-t", "raw", "-A", "PREROUTING", "-p", strconv.Itoa(proto), "-d", decoy.String(), "-j", "DROP"}
	if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
		log.Printf("raw: anti-leak rule not installed (kernel may forward the decoy dst): %v: %s", err, strings.TrimSpace(string(out)))
		return nil
	}
	log.Printf("raw: anti-leak rule installed (iptables raw PREROUTING -p %d -d %s DROP)", proto, decoy)
	return func() {
		del := append([]string(nil), args...)
		del[2] = "-D"
		_ = exec.Command("iptables", del...).Run()
	}
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
		if r.fecEnc != nil {
			r.fecEnc.addData(body) // buffered into an RS block; shards go out via the emit callback
			continue
		}
		r.writeOut(r.wire(body, peer.IP), peer)
	}
}

// netToTun receives raw packets on the AF_INET socket, strips the profile header,
// authenticates, and writes data frames into the TUN. Used for every configuration
// except a decoy server (which reads off the wire via afpacketToTun instead).
func (r *Raw) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := r.conn.ReadFromIP(buf)
		if err != nil {
			return err
		}
		if !r.pinnedPeer() { // a forged source can't be filtered by — the AEAD authenticates
			if peer := r.peer.Load(); peer != nil && !addr.IP.Equal(peer.IP) {
				continue // only the peer's packets are ours (raw sockets see all)
			}
		}
		r.handleRaw(buf[:n], addr)
	}
}

// afpacketToTun receives frames aimed at the decoy destination off the wire via
// AF_PACKET. A decoy dst is not a local address, so the kernel would drop it before
// an AF_INET raw socket; AF_PACKET taps the packet before the IP stack's dst check.
// Incoming IPv4 frames are filtered to our protocol and decoy dst, then handled just
// like netToTun. SOCK_DGRAM strips the link header, so each frame starts at the IP header.
func (r *Raw) afpacketToTun() error {
	buf := make([]byte, maxDatagram+64) // room for the IPv4 header ahead of the frame
	for {
		n, from, err := syscall.Recvfrom(r.pktFd, buf, 0)
		if err != nil {
			select {
			case <-r.closeCh:
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
		if int(pkt[9]) != r.proto {
			continue // not our carrier protocol
		}
		if r.decoy != nil && !net.IP(pkt[16:20]).Equal(r.decoy) {
			continue // only frames aimed at our decoy destination
		}
		src := &net.IPAddr{IP: append(net.IP(nil), pkt[12:16]...)}
		r.handleRaw(pkt[ihl:], src)
	}
}

// handleRaw strips the profile header, authenticates the frame, and dispatches it —
// the common tail of both receive paths (AF_INET and AF_PACKET). Frames that do not
// open as data are tried as handshake messages.
func (r *Raw) handleRaw(raw []byte, addr *net.IPAddr) {
	body, ok := rawDecap(r.profile, raw)
	if !ok {
		return
	}
	if r.fecDec != nil {
		// The two receive loops are the only readers, so rxAddr is stable for the
		// whole input() call (the decoder delivers recovered frames synchronously).
		r.rxAddr.Store(addr)
		r.fecDec.input(body)
		return
	}
	r.deliver(body, addr)
}

// deliver dispatches one received frame (already de-FEC'd and de-encap'd):
// authenticated data in crypto mode, or unauthenticated legacy framing in clear mode.
func (r *Raw) deliver(body []byte, addr *net.IPAddr) {
	if addr == nil {
		return
	}
	if r.cryptoOn {
		r.handleCrypto(body, addr)
		return
	}
	if len(body) < 2 || body[0] != magic {
		return
	}
	r.learnPeer(addr)
	r.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
}

// openWith tries to open one datagram under a specific session sealer, touching no
// session/replay state so a frame can be tried against both the live and a pending session.
func (r *Raw) openWith(s Sealer, body []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	if r.obfs {
		return obfsOpen(s, body)
	}
	if len(body) >= 2 && body[0] == magic {
		typ = body[1]
		session, seq, payload, oerr = s.Open(body[2:], []byte{typ})
		return
	}
	return 0, 0, 0, nil, errBadFrame
}

func (r *Raw) handleCrypto(body []byte, addr *net.IPAddr) {
	if s := r.sealer(); s != nil {
		if typ, session, seq, payload, oerr := r.openWith(s, body); oerr == nil && r.rp.ok(session, seq) {
			r.lastRx.Store(time.Now().UnixNano()) // liveness: the session is answering
			r.learnPeer(addr)
			r.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a PENDING session
	// staged by a recent init; promote it only when a frame actually opens under it, so a
	// replayed init cannot tear down the live session or its replay window.
	if r.pend != nil {
		if typ, session, seq, payload, oerr := r.openWith(r.pend.s, body); oerr == nil && r.pendRp.ok(session, seq) {
			r.session.Store(r.pend)
			r.rp = r.pendRp
			r.pend = nil
			r.lastRx.Store(time.Now().UnixNano())
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
	if !r.pinnedPeer() { // with a forged source/decoy the address is not the real peer — keep the configured one
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
		r.lastRx.Store(time.Now().UnixNano()) // baseline so the fresh session isn't instantly "stale"
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
	if r.pend != nil {
		if resp, ok := r.hsCache.get(body); ok {
			r.writeCtrl(resp, r.replyAddr(addr))
			return
		}
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
	// Stage the new session as PENDING; the live session and its replay window survive until
	// a frame actually opens under these new keys (see handleCrypto), so a replayed init
	// cannot wedge the tunnel. Peer rebinding is likewise deferred to that first frame.
	r.pend = &sealerBox{s: s}
	r.pendRp = replayGuard{}
	if r.localIP.Load() == nil {
		if lip := routeLocalIP(addr.IP); lip != nil {
			r.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	if msg2 := crypto.RespMsg(r.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while pend is
		// still current) is served without recomputing the crypto above. put copies body
		// (it aliases the receive buffer); msg2 is a fresh slice, safe to keep.
		r.hsCache.put(body, msg2)
		r.writeCtrl(msg2, r.replyAddr(addr))
	}
}

// writeCtrl profile-wraps and sends a control/handshake frame, tagging it passthrough
// under FEC so the peer's decoder forwards it straight through instead of parsing it as
// a shard. to may differ from the learned peer (a server's handshake reply, or a
// forged-source client's fixed reply address).
func (r *Raw) writeCtrl(body []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	r.writeOut(r.wire(fecTag(r.fecEnc, body), to.IP), to)
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

// sessionStale reports that the client has heard nothing authenticated from the server for long
// enough that the peer most likely restarted with a fresh session, so the client should drop its
// dead session and re-handshake. Without it a SERVER restart wedges the tunnel: the client keeps
// pinging under a key the fresh server can't open and never re-initiates. See Bip.sessionStale.
func (r *Raw) sessionStale() bool {
	last := r.lastRx.Load()
	if last == 0 {
		return false
	}
	w := 3 * r.keepalive
	if w < 10*time.Second {
		w = 10 * time.Second
	}
	return time.Since(time.Unix(0, last)) > w
}

func (r *Raw) clientLoop() {
	for {
		if r.cryptoOn && r.sealer() != nil && r.sessionStale() {
			r.session.Store(nil) // server likely restarted — drop the dead session so we re-handshake
			r.ci.Store(nil)
			log.Print("raw: no reply from the peer's session — re-handshaking (peer likely restarted)")
		}
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
	// Reuse the current ephemeral across retransmits — regenerate only for a fresh handshake
	// cycle (ci==nil). Regenerating each 1s retransmit races the reply on high-RTT links: the
	// resp (verified against the current ci) would always check against a newer ephemeral and
	// be dropped, so the handshake could never complete on exactly the throttled links we target.
	ci := r.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		r.ci.Store(ci)
	}
	r.writeCtrl(crypto.InitMsg(r.psk, ci), peer)
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
	r.writeCtrl(body, to)
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
