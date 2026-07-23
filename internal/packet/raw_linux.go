//go:build linux

// This file implements the "raw" transport: the same core frames as the UDP
// carrier (udp.go), but each frame is wrapped in a raw-IP profile header
// (rawEncap) and shipped over a raw IPv4 socket of the profile's protocol
// number instead of over UDP. It mirrors UDP's structure — ephemeral X25519
// handshake, replay guard, obfs and clear/crypto modes — so only the socket and
// the per-frame profile wrap differ.
//
// A raw socket needs CAP_NET_RAW (root). Because it receives EVERY packet of the
// chosen protocol addressed to the host, frames are filtered by peer source
// address and then authenticated by the inner AEAD; anything else is dropped.
package packet

import (
	"crypto/rand"
	"crypto/sha256"
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
	conn          *net.IPConn
	dev           *tun.Device
	keepalive     time.Duration
	deadAfterSecs int // per-tunnel self-heal deadline override (0 = default 3×keepalive/10s floor)
	obfs          bool
	cryptoOn      bool
	psk           string
	cipher        string
	profile       string
	isClient      bool
	icmpID        uint16 // ICMP echo identifier; PSK-derived + shared by both ends for the icmp profile so the server's replies match the client's requests through stateful ICMP filters (random for other profiles; the core itself ignores it on receive)
	spi           uint32 // per-session ESP Security Parameters Index (esp profile; constant like a real SA)

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

	localIP  atomic.Pointer[net.IPAddr] // our source IP toward the peer (for TCP/UDP checksums)
	peer     atomic.Pointer[net.IPAddr] // current known peer (server learns it)
	srcAllow map[string]struct{}        // server pool: the client's known source IPs (4-byte keys) it may rotate across; set once before Run, then read-only
	session  atomic.Pointer[sealerBox]
	rp       replayGuard
	staged   []*stagedBox // server: bounded set of sessions staged by recent inits, each promoted only once a frame opens under it
	hsCache  initCache    // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci       atomic.Pointer[crypto.Ephemeral]
	seq      atomic.Uint32
	// Synthetic-TCP-profile state (tcp profile only; ignored by the others): a per-session
	// ISN and a constant peer-ISN we "acknowledge", so the forged segments carry an advancing
	// sequence and a non-zero ACK — a live-established-flow look — instead of the tell-tale
	// seq+1 / ack=0 that a stateful DPI flags as forged.
	tcpISN   uint32
	tcpAck   uint32
	tcpBytes atomic.Uint32 // cumulative tcp-profile payload bytes; drives the realistic seq advance
	lastRx   atomic.Int64  // unix-nano of the last authenticated frame (client staleness)
	hbRx     atomic.Int64  // unix-nano of the last REAL inbound frame — feeds the status heartbeat; 0 until the peer answers (v2.48.7)
	// peerAnswered gates the clear-mode heal: set when the CURRENT endpoint replies, cleared on
	// rotation, so a just-jumped-to (unproven) endpoint's burn is never falsely cleared. Mirrors UDP.
	peerAnswered atomic.Bool

	fecEnc *fecEncoder                // non-nil when FEC is on: buffers data frames into RS blocks on send
	fecDec *fecDecoder                // non-nil when FEC is on: reassembles + reconstructs blocks on receive
	rxAddr atomic.Pointer[net.IPAddr] // src of the packet currently feeding fecDec (deliver reads it)

	sendMu   sync.RWMutex // senders RLock around the raw spoofFd Sendto; Close write-locks before closing it
	sendDown bool         // set under sendMu.Lock in Close: no more Sendto on the (about-to-be-closed) spoofFd

	// Fake-packet desync (client only). desync holds the decoy parameters; fakeFd is a
	// dedicated IP_HDRINCL socket for low-TTL decoys, opened only when desync is on AND
	// spoofing did not already open one to borrow (spoofFd) — -1 when unused. inj is an
	// AF_PACKET injector for bad-checksum decoys (IP_HDRINCL rewrites the checksum, so those
	// must bypass it); nil unless a badsum/both mode is on and the socket opened.
	desync desyncCfg
	fakeFd int
	inj    *l2inject

	closeCh   chan struct{}
	closeOnce sync.Once

	st *coreStatus // client-only: precise self-heal event ring written to the status file (nil = off)
	pp *PeerPool   // client-only: destination-IP rotation pool (nil = single fixed peer, no rotation)
	sp *PeerPool   // client-only: source-IP rotation pool (nil = fixed source; ignored under spoofSrc)
}

// SetDeadAfter (client) tightens the session-stale deadline to the per-tunnel dead_after_secs so the
// tunnel re-handshakes faster than the default (3×keepalive). No-op for secs<=0. Call before Run.
func (r *Raw) SetDeadAfter(secs int) {
	if secs > 0 {
		r.deadAfterSecs = secs
	}
}

// SetStatusPath (client, optional) wires a status-file event ring so self-heal re-handshakes and
// recoveries surface in the panel's system log. Call before Run(). No-op path leaves it off.
func (r *Raw) SetStatusPath(path string) {
	if path == "" || !r.isClient {
		return
	}
	peer := ""
	if p := r.peer.Load(); p != nil {
		peer = p.String()
	}
	r.st = newCoreStatus(path, "raw:"+r.profile+" · "+peer)
}

// SetDesync (client, optional) turns on fake-packet desync: `count` decoy packets go out
// just before each fresh handshake to mis-sync a stateful DPI. It needs an IP_HDRINCL
// socket to stamp the decoy TTL/checksum; when spoofing already opened one (spoofFd) it is
// reused, otherwise a dedicated socket is opened here. Failure to open only disables the
// decoys (it never fails the tunnel). Call before Run(). No-op on the server.
func (r *Raw) SetDesync(on bool, ttl, count int, mode string) {
	if !r.isClient {
		return
	}
	d := newDesyncCfg(on, ttl, count, mode)
	if !d.on {
		return
	}
	if r.spoofFd < 0 { // no spoof socket to borrow — open a dedicated one for the low-TTL decoys
		fd, err := openHdrincl(r.proto)
		if err != nil {
			log.Printf("raw: fake-desync disabled (cannot open raw socket: %v)", err)
			return
		}
		r.fakeFd = fd
	}
	if d.usesBadsum() { // bad-checksum decoys must bypass IP_HDRINCL (which repairs the checksum)
		if p := r.peer.Load(); p != nil {
			if inj, err := newL2Inject(p.IP); err != nil {
				log.Printf("raw: bad-checksum decoys disabled (AF_PACKET: %v) — TTL decoys still active", err)
			} else {
				r.inj = inj
			}
		}
	}
	r.desync = d
}

// sendFakes emits the configured decoy packets toward the peer just before a real
// handshake. Each decoy shares the real flow's src/dst/proto (mirroring writeOut's forge
// choices, so a DPI sees them as the same flow) with a per-decoy TTL/checksum and random
// payload. Guarded by sendMu/sendDown exactly like writeOut so Close can't race the fd shut.
func (r *Raw) sendFakes(to *net.IPAddr) {
	if !r.desync.on || to == nil {
		return
	}
	fd := r.spoofFd
	if fd < 0 {
		fd = r.fakeFd
	}
	src := r.srcIP()
	if r.spoofSrc != nil {
		src = r.spoofSrc
	}
	dst := to.IP
	if r.spoofDst != nil {
		dst = r.spoofDst
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	for _, sp := range r.desync.specs() {
		out := buildIP4Ext(src, dst, r.proto, sp.ttl, sp.badSum, fakePayload())
		if out == nil {
			continue
		}
		if sp.badSum {
			// Bad-checksum decoy: inject at L2 so the forged checksum survives (IP_HDRINCL
			// would repair it). Best-effort — a cold next-hop neighbour just drops this one;
			// the injector has its own fd guard, so it is safe against a concurrent Close.
			if r.inj != nil {
				_ = r.inj.send(out)
			}
			continue
		}
		if fd < 0 { // low-TTL decoy needs the IP_HDRINCL socket (opened in SetDesync)
			continue
		}
		r.sendMu.RLock()
		if !r.sendDown {
			_ = syscall.Sendto(fd, out, 0, &sa)
		}
		r.sendMu.RUnlock()
	}
}

func newRaw(conn *net.IPConn, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, isClient bool) *Raw {
	var idb [14]byte
	_, _ = rand.Read(idb[:])
	spi := binary.BigEndian.Uint32(idb[10:14])
	if spi < 256 {
		spi += 256 // SPIs 0..255 are IANA-reserved; a real SA uses >= 256
	}
	// ICMP profile: derive the echo identifier from the PSK so BOTH ends use the SAME id. A stateful
	// ICMP filter/conntrack (e.g. Iran's) only lets an echo REPLY through when its id matches an echo
	// REQUEST it saw leave; with per-process random ids the server's replies look unsolicited and get
	// dropped, so the tunnel never establishes. A shared PSK-derived id makes the server's replies
	// match the client's requests and pass stateful ICMP tracking. Other profiles don't use icmpID.
	icmpID := binary.BigEndian.Uint16(idb[0:2])
	if profile == "icmp" {
		h := sha256.Sum256([]byte("tnl-core|v2|icmp-id|" + psk))
		icmpID = binary.BigEndian.Uint16(h[0:2])
	}
	return &Raw{
		conn: conn, dev: dev, keepalive: ka, obfs: obfs, cryptoOn: cryptoOn,
		psk: psk, cipher: cipher, profile: profile, isClient: isClient, spoofFd: -1, pktFd: -1, fakeFd: -1,
		icmpID: icmpID, closeCh: make(chan struct{}),
		tcpISN: binary.BigEndian.Uint32(idb[2:6]), tcpAck: binary.BigEndian.Uint32(idb[6:10]), spi: spi,
	}
}

// DialRaw (client role) opens a raw socket of the profile's protocol and targets
// peerIP. peerIP may be a plain IPv4 or an "ip:port" (the port is ignored — raw
// IP has no ports of its own; the tcp/udp profiles carry synthetic ones).
func DialRaw(peerIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile, spoofSrc, spoofDst string, fec bool, fecData, fecParity, rawProto int) (*Raw, error) {
	proto, ok := rawEffProto(profile, rawProto)
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
func ListenRaw(listenIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile, realPeer, spoofDst string, fec bool, fecData, fecParity, rawProto int) (*Raw, error) {
	proto, ok := rawEffProto(profile, rawProto)
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
	if realPeer != "" { // client forges its source, so we can't learn it — reply to this real IP
		pip := parseIP4(hostOnly(realPeer))
		if pip == nil {
			conn.Close()
			return nil, fmt.Errorf("raw: real_peer_ip %q is not an IPv4 address", realPeer)
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
		r.st.setDW(int64(r.deadWin().Seconds())) // publish the resolved dead-window so the reader ages hb against it
		go heartbeat(r.st, &r.hbRx, r.closeCh)   // publish lastRx to the status file so an idle tunnel reads live, not half-open
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
	if r.fakeFd >= 0 { // dedicated desync socket (only set when spoofFd wasn't, so never the same fd)
		syscall.Close(r.fakeFd)
	}
	if r.inj != nil { // AF_PACKET bad-checksum injector (its own fd guard makes this Close-safe)
		r.inj.close()
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
	return sealBody(r.sealer(), r.obfs, typ, payload, padMaxFor(typ))
}

// wire wraps a framed body in the profile carrier header, ready for the socket.
func (r *Raw) wire(body []byte, dst net.IP) []byte {
	var seq, ack uint32
	if r.proto == protoTCP {
		// advance the sequence by this segment's payload length (a real byte stream) and
		// acknowledge a constant peer ISN — the synthetic flow receives nothing, so a real
		// ACK number would stay put. tcpBytes.Add returns the post-add total; minus n yields
		// the pre-segment offset, so concurrent sends get non-overlapping sequence ranges.
		n := uint32(len(body))
		seq = r.tcpISN + r.tcpBytes.Add(n) - n
		ack = r.tcpAck
	} else {
		seq = r.seq.Add(1)
	}
	return rawEncap(r.profile, body, r.srcIP(), dst, r.isClient, r.icmpID, seq, ack, r.spi)
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

// buildIP4 assembles an IPv4 header (TTL 64, valid checksum) in front of payload.
func buildIP4(src, dst net.IP, proto int, payload []byte) []byte {
	return buildIP4Ext(src, dst, proto, 64, false, payload)
}

// buildIP4Ext is buildIP4 with an explicit TTL and an option to store a deliberately
// WRONG header checksum — the two knobs a fake-packet desync needs: a low TTL makes a
// decoy expire a few hops out (before the server), and a bad checksum makes the server's
// IP stack drop it. ttl is clamped to 1..255. With ttl=64 and badSum=false it is byte-for-
// byte identical to the original buildIP4, so the normal carrier path is unchanged.
func buildIP4Ext(src, dst net.IP, proto, ttl int, badSum bool, payload []byte) []byte {
	if len(payload) > 0xffff-20 {
		return nil // the IPv4 total-length field is 16-bit; refuse rather than truncate it (MTU-bounded, so defensive)
	}
	if ttl < 1 {
		ttl = 1
	} else if ttl > 255 {
		ttl = 255
	}
	h := make([]byte, 20+len(payload))
	h[0] = 0x45 // version 4, IHL 5 (no options)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))
	h[8] = byte(ttl)
	h[9] = byte(proto)
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	sum := onesComplementSum(h[:20]) // checksum field is 0 during the sum
	binary.BigEndian.PutUint16(h[10:12], sum)
	if badSum {
		// Corrupt it so an on-path DPI / the receiver's IP stack sees an invalid checksum.
		// ^sum alone is NOT always wrong: one's complement has two representations of zero
		// (0x0000 and 0xffff both verify), so when the correct sum is 0x0000 its complement
		// 0xffff still validates. Store the complement, then verify it actually fails (the
		// whole header must NOT sum to zero) and flip a bit if we hit that zero-twin case.
		binary.BigEndian.PutUint16(h[10:12], ^sum)
		if onesComplementSum(h[:20]) == 0 {
			binary.BigEndian.PutUint16(h[10:12], ^sum^0x0001)
		}
	}
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
			if peer := r.peer.Load(); peer != nil && !addr.IP.Equal(peer.IP) && !r.srcAllowed(addr.IP) {
				continue // only the peer's packets are ours (raw sockets see all); a pooled server also
				// admits the client's other known source IPs so a source rotation reaches crypto and re-binds
			}
		}
		r.handleRaw(buf[:n], addr)
	}
}

// afpacketToTun receives frames aimed at the decoy destination off the wire via
// AF_PACKET. A decoy dst is not a local address, so the kernel would drop it before
// an AF_INET raw socket; AF_PACKET taps the packet before the IP stack's dst check.
// afpacketLoop owns the AF_PACKET receive loop shared by the raw and flux carriers: one reusable
// buffer, the blocking Recvfrom, the close/EINTR/EAGAIN control flow, the PACKET_OUTGOING self-frame
// skip, and the IPv4 header validation. It calls handle(pkt, ihl) for each accepted IPv4 frame; the
// carrier-specific per-frame `continue`s become plain returns from handle. Runs until Close (nil) or a
// real Recvfrom error.
func afpacketLoop(fd int, closeCh <-chan struct{}, handle func(pkt []byte, ihl int)) error {
	buf := make([]byte, maxDatagram+64) // room for the IPv4 header ahead of the frame
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			select {
			case <-closeCh:
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
		handle(pkt, ihl)
	}
}

// Incoming IPv4 frames are filtered to our protocol and decoy dst, then handled just
// like netToTun. SOCK_DGRAM strips the link header, so each frame starts at the IP header.
func (r *Raw) afpacketToTun() error {
	return afpacketLoop(r.pktFd, r.closeCh, func(pkt []byte, ihl int) {
		if int(pkt[9]) != r.proto {
			return // not our carrier protocol
		}
		if r.decoy != nil && !net.IP(pkt[16:20]).Equal(r.decoy) {
			return // only frames aimed at our decoy destination
		}
		src := &net.IPAddr{IP: append(net.IP(nil), pkt[12:16]...)}
		r.handleRaw(pkt[ihl:], src)
	})
}

// handleRaw strips the profile header, authenticates the frame, and dispatches it —
// the common tail of both receive paths (AF_INET and AF_PACKET). Frames that do not
// open as data are tried as handshake messages.
func (r *Raw) handleRaw(raw []byte, addr *net.IPAddr) {
	body, ok := rawDecap(r.profile, r.proto, raw)
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
	r.markRx()                 // the peer is answering (clear mode has no session to prove it)
	r.peerAnswered.Store(true) // this endpoint has replied since we pointed at it -> safe to heal its burn
	r.learnPeer(addr)
	r.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
}

// openWith tries to open one datagram under a specific session sealer, touching no
// session/replay state so a frame can be tried against both the live and a pending session.
func (r *Raw) openWith(s Sealer, body []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, body, r.obfs)
}

func (r *Raw) handleCrypto(body []byte, addr *net.IPAddr) {
	if s := r.sealer(); s != nil {
		if typ, session, seq, payload, oerr := r.openWith(s, body); oerr == nil && r.rp.ok(session, seq) {
			r.markRx() // the session is answering
			r.learnPeer(addr)
			r.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a session STAGED by a recent
	// init; promote a candidate only when a frame actually opens under it, so a replayed init cannot
	// tear down the live session or its replay window. The live session was tried first above, so an
	// established tunnel never reaches this loop; on the normal path the set holds one candidate.
	for _, st := range r.staged {
		if typ, session, seq, payload, oerr := r.openWith(st.box.s, body); oerr == nil && st.rp.ok(session, seq) {
			r.session.Store(st.box)
			r.rp = st.rp
			r.staged = nil
			r.markRx() // a pending session promoted -> genuine inbound
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
	// Keep the configured/rotated peer when: a forged source/decoy means the reply address isn't the
	// real peer (pinnedPeer), OR a destination pool owns the peer (r.pp) — a pool server can answer
	// from a different IP than the client dialed, and adopting it would pull the client off the pool.
	if !r.pinnedPeer() && r.pp == nil {
		r.peer.Store(addr)
	}
	r.learnLocalIP(addr.IP)
}

// learnLocalIP records, once, the local source IP the kernel routes toward peer — the tcp profile's
// checksum needs it. Idempotent: a no-op after the first success, so repeated inbound frames and a
// staged pending session don't re-resolve it.
func (r *Raw) learnLocalIP(peer net.IP) {
	if r.localIP.Load() == nil {
		if lip := routeLocalIP(peer); lip != nil {
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
		// Clear the ephemeral so a replayed resp captured on-path hits the ci==nil guard above
		// instead of re-parsing and wiping the fresh anti-replay window. A legitimate
		// re-handshake regenerates a fresh ci in sendInit (ci==nil path).
		r.ci.Store(nil)
		r.markRx()              // server RESP arrived: genuine inbound (green on a real connect)
		r.st.reconnected("raw") // recovery after a self-heal (nil-safe; silent on first connect)
		return
	}
	// Compute-DoS mitigation: an attacker replaying captured valid inits at high rate
	// would otherwise force a fresh ECDH+HKDF (GenerateEphemeral+SessionSealer) per packet.
	// If this init matches one we recently answered (while a pending session is current),
	// re-send the already-computed response and return before that expensive crypto. The
	// handshake outcome is unchanged (staged/promote-on-open is untouched); a genuinely new
	// init falls through to the full handshake below. The cache is a small LRU (not a
	// single entry) so alternating two captured inits cannot bust it. It is touched only on
	// this single receive goroutine (like staged), so no locking is needed.
	if len(r.staged) > 0 {
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
	r.staged = stageSession(r.staged, s)
	r.learnLocalIP(addr.IP)
	if msg2 := crypto.RespMsg(r.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while a staged session
		// is still current) is served without recomputing the crypto above. put copies body
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
// pinging under a key the fresh server can't open and never re-initiates. See UDP.sessionStale.
func (r *Raw) deadWin() time.Duration { return sessionStaleWindow(r.keepalive, r.deadAfterSecs) }
func (r *Raw) sessionStale() bool     { return staleSince(r.lastRx.Load(), r.deadWin()) }

// markRx stamps a genuine inbound frame: both the failover clock (lastRx) and the liveness heartbeat
// (hbRx). hbRx is set ONLY here (proven inbound), so hb stays 0 until the peer answers — a connecting
// tunnel reads yellow, not a false green. Failover-clock seeds (connect / rotation) must NOT call this.
func (r *Raw) markRx() {
	now := time.Now().UnixNano()
	r.lastRx.Store(now)
	r.hbRx.Store(now)
}

// SetPeerPool (client) wires a destination-IP rotation pool: a peer whose handshake never completes
// is burned and the client re-points at the next live endpoint (a proactive timer also rotates).
// nil / single-endpoint = no rotation. Rotates only the DESTINATION; a spoofed source (bip) is
// unaffected. main wires it via the shared SetPeerPool type assertion.
func (r *Raw) SetPeerPool(pp *PeerPool) {
	if r.isClient {
		r.pp = pp
	}
}

// SetPeerSources (SERVER) records the client's known SOURCE-pool IPs so the receive filter admits a
// rotated-but-expected client source (which then authenticates via crypto and re-binds the peer),
// instead of dropping it as an unrelated host. Call before Run(); no-op on the client / empty list.
func (r *Raw) SetPeerSources(ips []string) {
	if r.isClient || len(ips) == 0 {
		return
	}
	if m := buildSrcAllow(ips); len(m) > 0 {
		r.srcAllow = m
	}
}

// srcAllowed reports whether ip is one of the client's known pool sources (server only). Empty set
// (non-pool tunnel, or the client) => false, so the strict single-source filter is unchanged there.
func (r *Raw) srcAllowed(ip net.IP) bool {
	return srcAllowedIn(r.srcAllow, ip)
}

// buildSrcAllow builds the server-side source-IP admit set from a pool's source IPs, keyed by bare
// 4-byte IPv4. Shared by the raw and flux carriers, whose SetPeerSources map-build was byte-identical.
func buildSrcAllow(ips []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ips))
	for _, s := range ips {
		if ip := parseIP4(hostOnly(s)); ip != nil {
			m[string(ip.To4())] = struct{}{}
		}
	}
	return m
}

// srcAllowedIn reports whether ip is in the admit set. An empty set => false, keeping the strict
// single-source filter unchanged. Shared by raw/flux srcAllowed.
func srcAllowedIn(set map[string]struct{}, ip net.IP) bool {
	if len(set) == 0 {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	_, ok := set[string(v4)]
	return ok
}

// SetSourcePool (client) wires a source-IP rotation pool: the crafted-header source the client sends
// FROM is cycled/burned alongside the destination. raw stamps the source per packet, so a rotation is
// an atomic swap (no socket rebind); the server follows the new source. IGNORED when spoofSrc is set —
// a forged source is a deliberate decoy that must not be rotated away. Call before Run().
func (r *Raw) SetSourcePool(sp *PeerPool) {
	if !r.isClient || r.spoofSrc != nil {
		return
	}
	r.sp = sp
	// Seed the initial source so the client stamps SrcIPs[0] from the first packet (matching the pool's
	// cur=0), instead of the route-derived default until the first rotation. Called before Run(), so
	// the later `if localIP==nil` guards (learnPeer/tryHandshake) then leave this in place.
	if sp != nil {
		if ip := parseIP4(hostOnly(sp.current())); ip != nil {
			r.localIP.Store(&net.IPAddr{IP: ip})
		}
	}
}

// rotateSourceRaw points the client at the next source-pool IP and swaps the crafted-header source.
// No session reset (the source is independent of the AEAD session). No-op when the pool did not move,
// the IP is not v4, or a spoofed source is in force.
func (r *Raw) rotateSourceRaw(proactive bool) {
	if r.sp == nil || r.spoofSrc != nil {
		return
	}
	addr, moved := r.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := parseIP4(hostOnly(addr))
	if ip == nil {
		return
	}
	r.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("raw: rotated source to %s", addr)
	// Source swap keeps the same AEAD session (no re-handshake) -> no matching reconnect. Use event() not
	// down() so wasDown isn't armed (a phantom recovery), and carry the new source IP for the panel log.
	r.st.event("down", "src-rotate", "ip:"+addr)
}

// rotatePeerRaw points the client at the next pool endpoint and clears the session so the next loop
// re-handshakes against the new destination. No-op when the pool did not move or the endpoint is not
// valid IPv4 (raw is IPv4-only).
func (r *Raw) rotatePeerRaw(proactive bool) {
	if r.pp == nil {
		return
	}
	addr, moved := r.pp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := parseIP4(hostOnly(addr))
	if ip == nil {
		return
	}
	r.peer.Store(&net.IPAddr{IP: ip})
	r.st.setActive("raw:" + r.profile + " · " + ip.String()) // refresh the frozen active descriptor to the new destination (matches SetStatusPath)
	r.session.Store(nil)
	r.ci.Store(nil)
	// Give the jumped-to endpoint a FRESH staleness window and mark it unproven, so a proactive jump
	// onto a dead endpoint fails over within the dead window instead of stranding (clear mode), and its
	// burn isn't healed until it actually replies. Mirrors rotatePeerUDP.
	r.lastRx.Store(time.Now().UnixNano())
	r.peerAnswered.Store(false)
	log.Printf("raw: rotated destination to %s", addr)
	r.st.down("peer-rotate", "ip:"+addr) // clears the session -> re-handshake -> reconnect pairs the down
}

// adoptPeerRaw re-points the client at the pool's CURRENT destination — used when an operator pin has
// just jumped the pool to a chosen endpoint — and clears the session so the next loop re-handshakes there.
func (r *Raw) adoptPeerRaw() {
	if r.pp == nil {
		return
	}
	ip := parseIP4(hostOnly(r.pp.current()))
	if ip == nil {
		return
	}
	r.peer.Store(&net.IPAddr{IP: ip})
	r.st.setActive("raw:" + r.profile + " · " + ip.String()) // refresh the frozen active descriptor to the new destination (matches SetStatusPath)
	r.session.Store(nil)
	r.ci.Store(nil)
	log.Printf("raw: pinned destination to %s", ip)
	r.st.down("peer-pin", "ip:"+ip.String()) // clears the session -> re-handshake -> reconnect pairs the down
}

// adoptSourceRaw swaps the crafted-header source to the pool's CURRENT source (an operator source pin).
// Ignored under spoofSrc (a forged source is a deliberate decoy, like rotateSourceRaw); no session reset.
func (r *Raw) adoptSourceRaw() {
	if r.sp == nil || r.spoofSrc != nil {
		return
	}
	ip := parseIP4(hostOnly(r.sp.current()))
	if ip == nil {
		return
	}
	r.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("raw: pinned source to %s", ip)
	r.st.event("down", "src-pin", "ip:"+ip.String()) // source pin: session survives, no reconnect (see rotateSourceRaw)
}

// ProbeAllNow retests every suspect/dead endpoint on both pools at once (the panel "probe now" control,
// delivered as SIGHUP). No-op unless pooled.
func (r *Raw) ProbeAllNow() {
	probeAllPools(r.pp, r.sp)
}

// pinPollLoop polls the pools' cmd files on a 1s ticker and applies any operator pin. Runs until Close.
func (r *Raw) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, r.closeCh, r.adoptPeerRaw, r.adoptSourceRaw)
}

func (r *Raw) clientLoop() {
	failN := 0
	rc := newRotationController(r.pp, r.sp)
	if rc.active() {
		go r.pinPollLoop(rc)
	}
	// Seed the staleness baseline NOW (clear mode). Without it, sessionStale() returns false while
	// lastRx==0, so a clear-mode failover-only pool whose first endpoint is dead never fires. Mirrors UDP.
	r.lastRx.Store(time.Now().UnixNano())
	for {
		if r.cryptoOn && r.sealer() != nil && r.sessionStale() {
			r.session.Store(nil) // server likely restarted — drop the dead session so we re-handshake
			r.ci.Store(nil)
			log.Print("raw: no reply from the peer's session — re-handshaking (peer likely restarted)")
			r.st.down("stale", "raw") // precise reason for the panel log (nil-safe when off)
		}
		// Clear mode has no handshake whose failure would drive failover, so a dead pool endpoint would
		// otherwise strand the tunnel forever. Use receive-staleness: the peer pongs our pings, so once it
		// stops answering (lastRx ages past the dead window) burn and advance the pool. Mirrors UDP.
		if !r.cryptoOn && rc.active() && r.sessionStale() {
			rc.fail(r.rotatePeerRaw, r.rotateSourceRaw)
			r.lastRx.Store(time.Now().UnixNano()) // fresh window even if the pool couldn't move (single endpoint / source-only)
			r.peerAnswered.Store(false)           // stale -> the current endpoint is no longer proven answering
			r.st.down("stale", "raw")
		}
		if r.cryptoOn && r.sealer() == nil {
			r.sendInit()
			if failN++; rc.active() && failN >= peerFailThreshold {
				rc.fail(r.rotatePeerRaw, r.rotateSourceRaw)
				failN = 0
			}
		} else {
			// Heal transient burns on endpoints proving themselves. Crypto signals via a completed
			// handshake (failN>0); clear mode has no handshake, so use the data plane (peerAnswered set
			// when the CURRENT endpoint replies, cleared on rotation) so a just-jumped-to endpoint's burn
			// is never falsely cleared. Mirrors UDP.
			if failN > 0 || (!r.cryptoOn && rc.active() && r.peerAnswered.Load()) {
				healEvents(r.st, rc)
			}
			failN = 0
			r.send(typePing, nil, r.peer.Load())
			rc.proactive(r.rotatePeerRaw, r.rotateSourceRaw, time.Now())
			if r.cryptoOn && r.sealer() == nil {
				// A proactive DESTINATION rotation just cleared the crypto session — loop back NOW to send
				// the re-handshake init immediately, instead of first sleeping the 1s retransmit interval
				// below, so the rotation gap is ~1 RTT rather than ~1s (matters for live streams). Clear
				// mode has no session/handshake so this never fires there; a duplicated init is harmless.
				continue
			}
		}
		wait := keepaliveInterval(r.keepalive, r.psk)
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
		// Fresh handshake cycle (not a 1s retransmit): desync the DPI right before the init.
		r.sendFakes(peer)
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
