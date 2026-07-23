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
	dev           *tun.Device
	keepalive     time.Duration
	deadAfterSecs int // per-tunnel self-heal deadline override (0 = default 3×keepalive/10s floor)
	rotate        time.Duration
	obfs          bool
	cryptoOn      bool
	psk           string
	cipher        string
	isClient      bool

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
	srcAllow map[string]struct{}        // server pool: the client's known source IPs (4-byte keys) it may rotate across; set once before Run, then read-only
	session  atomic.Pointer[sealerBox]
	curShape atomic.Pointer[fluxShape] // this epoch's shape (refreshed each second by rotateWatcher)
	rp       replayGuard
	staged   []*stagedBox // server: bounded set of sessions staged by recent inits, each promoted only once a frame opens under it
	hsCache  initCache    // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci       atomic.Pointer[crypto.Ephemeral]
	lastRx   atomic.Int64 // unix-nano of the last authenticated frame (client staleness)
	hbRx     atomic.Int64 // unix-nano of the last REAL inbound frame — feeds the status heartbeat; 0 until the peer answers (v2.48.7)
	// peerAnswered gates the clear-mode heal: set when the CURRENT endpoint replies, cleared on
	// rotation, so a just-jumped-to (unproven) endpoint's burn is never falsely cleared. Mirrors UDP.
	peerAnswered atomic.Bool
	logEp        atomic.Int64 // last epoch whose rotation was logged (rotation visibility)

	antiLeak   atomic.Pointer[func()] // anti-ICMP cleanup for the CURRENT peer; swapped on each re-scope, read in Close
	leakMu     sync.Mutex             // serializes anti-leak re-scoping (rotate/pin/learnPeer) vs Close
	antiLeakIP net.IP                 // the IP the current anti-leak rule is scoped to (guarded by leakMu); nil = none
	sendMu     sync.RWMutex           // senders RLock around the raw-fd Sendto; Close takes the write lock before closing it
	sendDown   bool                   // set under sendMu.Lock in Close: no more Sendto on the (about-to-be-closed) raw fd
	desync     desyncCfg              // client-only fake-packet desync (decoys emitted before each handshake); zero value = off
	inj        *l2inject              // AF_PACKET injector for bad-checksum decoys (IP_HDRINCL repairs the checksum); nil unless a badsum/both mode is on
	closeCh    chan struct{}
	closeOnce  sync.Once

	st *coreStatus // client-only: precise self-heal event ring written to the status file (nil = off)
	pp *PeerPool   // client-only: destination-IP rotation pool (nil = single fixed peer, no rotation)
	sp *PeerPool   // client-only: source-IP rotation pool (nil = single fixed source; swaps the crafted header src)
}

// SetDeadAfter (client) tightens the session-stale deadline to the per-tunnel dead_after_secs so the
// tunnel re-handshakes faster than the default (3×keepalive). No-op for secs<=0. Call before Run.
func (f *Flux) SetDeadAfter(secs int) {
	if secs > 0 {
		f.deadAfterSecs = secs
	}
}

// SetStatusPath (client, optional) wires a status-file event ring so self-heal re-handshakes and
// recoveries surface in the panel's system log. Call before Run(). No-op path leaves it off.
func (f *Flux) SetStatusPath(path string) {
	if path == "" || !f.isClient {
		return
	}
	peer := ""
	if p := f.peer.Load(); p != nil {
		peer = p.String()
	}
	f.st = newCoreStatus(path, "flux:"+f.carrier+" · "+peer)
}

// SetDesync (client, optional) turns on fake-packet desync: `count` decoy packets go out
// just before each fresh handshake to mis-sync a stateful DPI. flux always has its
// IP_HDRINCL send socket (sendFd), so no extra socket is needed. Call before Run(). No-op
// on the server.
func (f *Flux) SetDesync(on bool, ttl, count int, mode string) {
	if !f.isClient {
		return
	}
	d := newDesyncCfg(on, ttl, count, mode)
	if d.usesBadsum() { // bad-checksum decoys must bypass IP_HDRINCL (which repairs the checksum)
		if p := f.peer.Load(); p != nil {
			if inj, err := newL2Inject(p.IP); err != nil {
				log.Printf("flux: bad-checksum decoys disabled (AF_PACKET: %v) — TTL decoys still active", err)
			} else {
				f.inj = inj
			}
		}
	}
	f.desync = d
}

// sendFakes emits the configured decoy packets to the peer just before a real handshake,
// each shaped like this epoch's carrier (raw proto / udp+ports / stun) with a per-decoy
// TTL/checksum and random payload, so a DPI sees them as the same flow. Reuses the
// IP_HDRINCL send socket and the same sendMu/sendDown guard as carrierOut. flux never
// forges addresses, so src/dst are the real ones.
func (f *Flux) sendFakes(to *net.IPAddr) {
	if !f.desync.on || to == nil || f.sendFd < 0 {
		return
	}
	sh := f.curShape.Load()
	if sh == nil {
		return
	}
	src := f.srcIP()
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	for _, sp := range f.desync.specs() {
		body := fakePayload()
		proto, seg := f.carrierSeg(body, sh, src, to.IP)
		out := buildIP4Ext(src, to.IP, proto, sp.ttl, sp.badSum, seg)
		if out == nil {
			continue
		}
		if sp.badSum {
			// Bad-checksum decoy: inject at L2 so the forged checksum survives (IP_HDRINCL
			// would repair it). Best-effort; the injector guards its own fd against Close.
			if f.inj != nil {
				_ = f.inj.send(out)
			}
			continue
		}
		f.sendMu.RLock()
		if !f.sendDown {
			_ = syscall.Sendto(f.sendFd, out, 0, &sa)
		}
		f.sendMu.RUnlock()
	}
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
	// Seed logEp to the startup epoch so rotateWatcher logs the FIRST genuine rotation — even one that
	// lands before its first tick — instead of the prev==0 guard swallowing it as the startup seed; the
	// startup epoch itself stays unlogged because the first same-epoch tick then sees prev==sh.epoch.
	f.logEp.Store(sh.epoch)
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
	f.setAntiLeak(ip) // the peer is known up front — suppress kernel ICMP for its frames now
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
		f.st.setDW(int64(f.deadWin().Seconds())) // publish the resolved dead-window so the reader ages hb against it
		go heartbeat(f.st, &f.hbRx, f.closeCh)   // publish lastRx to the status file so an idle tunnel reads live, not half-open
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
	// closeCh is already closed (closeOnce above), so any setAntiLeak that now acquires leakMu bails
	// out; taking leakMu here orders us after an in-flight re-scope so we remove whatever rule it left.
	f.leakMu.Lock()
	if p := f.antiLeak.Load(); p != nil && *p != nil {
		(*p)()
	}
	f.antiLeak.Store(nil)
	f.leakMu.Unlock()
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
	if f.inj != nil { // AF_PACKET bad-checksum injector (its own fd guard makes this Close-safe)
		f.inj.close()
	}
	return nil
}

// setAntiLeak scopes the raw-PREROUTING DROP rule to `peer` so the kernel does not answer this
// carrier's exotic protocol / unbound UDP port with an ICMP unreachable. AF_PACKET taps every frame
// before that chain runs, so flux still receives everything. The rule is scoped to the carrier's own
// protocol/ports (NOT all traffic from the peer) so a co-located tunnel to the same peer — e.g. a
// raw/bip link on proto 253 — is not collaterally dropped.
//
// Unlike a one-shot install, this RE-SCOPES on demand: an IP-rotation pool changes the peer (the
// client's destination, or the client source a server follows), and a rule left on the OLD peer would
// let the kernel ICMP-leak on the NEW one. Called per authenticated frame (learnPeer) and up front on
// dial, it is idempotent — a no-op while the peer is unchanged — and on a change it removes the old
// rule before adding the new one. Best-effort; a failed iptables call only means the kernel may leak.
func (f *Flux) setAntiLeak(peer net.IP) {
	v4 := peer.To4()
	if v4 == nil {
		return
	}
	f.leakMu.Lock()
	defer f.leakMu.Unlock()
	select {
	case <-f.closeCh:
		return // shutting down: don't install a rule Close won't clean up
	default:
	}
	if f.antiLeakIP != nil && f.antiLeakIP.Equal(v4) {
		return // already scoped to this peer — no iptables churn on every frame
	}
	if old := f.antiLeak.Load(); old != nil && *old != nil {
		(*old)() // remove the rule scoped to the PREVIOUS peer before re-scoping
	}
	fn := addFluxDrop(v4, f.carrier)
	f.antiLeak.Store(&fn)
	f.antiLeakIP = append(net.IP(nil), v4...)
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

// carrierSeg maps the configured carrier to the (IP proto, L4 payload) that frames body under shape
// sh: raw tunnels body directly under the epoch's rotating IP protocol; udp/stun wrap it in a UDP
// segment (stun prepends a STUN Binding header so the flow reads as WebRTC signalling). Shared by the
// real send path (carrierOut) and the decoy path (sendFakes) so the two can never drift on how a
// carrier frames a packet — a DPI must see the decoys shaped exactly like the real traffic.
func (f *Flux) carrierSeg(body []byte, sh *fluxShape, src, dst net.IP) (proto int, payload []byte) {
	switch f.carrier {
	case "raw":
		return sh.proto, body
	case "stun":
		return protoUDP, buildUDPSeg(src, dst, sh.sport, sh.dportSTUN, buildSTUN(body))
	default: // udp
		return protoUDP, buildUDPSeg(src, dst, sh.sport, sh.dport, body)
	}
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
	proto, seg := f.carrierSeg(body, sh, src, to.IP)
	out := buildIP4(src, to.IP, proto, seg)
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
		if peer := f.peer.Load(); peer != nil && !src.IP.Equal(peer.IP) && !f.srcAllowed(src.IP) {
			// only the peer's frames are ours (AF_PACKET sees all hosts); a pooled server ALSO admits the
			// client's other known source IPs so a source rotation reaches crypto and learnPeer re-binds.
			continue
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
		f.markRx()                 // the peer is answering (clear mode has no session to prove it)
		f.peerAnswered.Store(true) // this endpoint has replied since we pointed at it -> safe to heal its burn
		f.learnPeer(addr)
		f.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
		return
	}
	if s := f.sealer(); s != nil {
		if typ, session, seq, payload, oerr := f.openWith(s, body); oerr == nil && f.rp.ok(session, seq) {
			f.markRx() // the session is answering
			f.learnPeer(addr)
			f.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a session STAGED by a recent
	// init; promote a candidate only when a frame actually opens under it, so a replayed init cannot
	// tear down the live session or its replay window. The live session was tried first above, so an
	// established tunnel never reaches this loop; on the normal path the set holds one candidate.
	for _, st := range f.staged {
		if typ, session, seq, payload, oerr := f.openWith(st.box.s, body); oerr == nil && st.rp.ok(session, seq) {
			f.session.Store(st.box)
			f.rp = st.rp
			f.staged = nil
			f.markRx() // a pending session promoted -> genuine inbound
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
	// The destination pool owns the client's peer: don't rebind it from a reply's source (a pool
	// server can answer from a different IP than the client dialed). Servers (pp==nil) still learn the
	// client here, which is what lets them follow a client's SOURCE rotation.
	if f.pp == nil {
		f.peer.Store(addr)
	}
	f.learnLocalIP(addr.IP)
	f.setAntiLeak(addr.IP)
}

// learnLocalIP records, once, the local source IP the kernel routes toward peer — the tcp profile's
// checksum needs it. Idempotent: a no-op after the first success, so repeated inbound frames and a
// staged pending session don't re-resolve it.
func (f *Flux) learnLocalIP(peer net.IP) {
	if f.localIP.Load() == nil {
		if lip := routeLocalIP(peer); lip != nil {
			f.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
}

// openWith tries to open one datagram under a specific session sealer, touching no
// session/replay state so a frame can be tried against both the live and a pending session.
func (f *Flux) openWith(s Sealer, body []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, body, f.obfs)
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
		// Clear the ephemeral so a replayed resp captured on-path hits the ci==nil guard above
		// instead of re-parsing and wiping the fresh anti-replay window. A legitimate
		// re-handshake regenerates a fresh ci in sendInit (ci==nil path).
		f.ci.Store(nil)
		f.markRx()               // server RESP arrived: genuine inbound (green on a real connect)
		f.st.reconnected("flux") // recovery after a self-heal (nil-safe; silent on first connect)
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
	if len(f.staged) > 0 {
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
	f.staged = stageSession(f.staged, s)
	f.learnLocalIP(addr.IP)
	if msg2 := crypto.RespMsg(f.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while a staged session
		// is still current) is served without recomputing the crypto above. put copies body
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
func (f *Flux) deadWin() time.Duration { return sessionStaleWindow(f.keepalive, f.deadAfterSecs) }
func (f *Flux) sessionStale() bool     { return staleSince(f.lastRx.Load(), f.deadWin()) }

// markRx stamps a genuine inbound frame: both the failover clock (lastRx) and the liveness heartbeat
// (hbRx). hbRx is set ONLY here (proven inbound), so hb stays 0 until the peer answers — a connecting
// tunnel reads yellow, not a false green. Failover-clock seeds (connect / rotation) must NOT call this.
func (f *Flux) markRx() {
	now := time.Now().UnixNano()
	f.lastRx.Store(now)
	f.hbRx.Store(now)
}

// SetPeerPool (client) wires a destination-IP rotation pool: a peer whose handshake never completes
// is burned and the client re-points at the next live endpoint (a proactive timer also rotates).
// nil / single-endpoint = no rotation. main wires it via the shared SetPeerPool type assertion.
func (f *Flux) SetPeerPool(pp *PeerPool) {
	if f.isClient {
		f.pp = pp
	}
}

// SetPeerSources (SERVER) records the client's known SOURCE-pool IPs so the receive filter admits a
// rotated-but-expected client source (which then authenticates via crypto and re-binds the peer),
// instead of dropping it as an unrelated host. Call before Run(); no-op on the client / empty list.
func (f *Flux) SetPeerSources(ips []string) {
	if f.isClient || len(ips) == 0 {
		return
	}
	if m := buildSrcAllow(ips); len(m) > 0 {
		f.srcAllow = m
	}
}

// srcAllowed reports whether ip is one of the client's known pool sources (server only). Empty set
// (non-pool tunnel, or the client) => false, so the strict single-source filter is unchanged there.
func (f *Flux) srcAllowed(ip net.IP) bool {
	return srcAllowedIn(f.srcAllow, ip)
}

// SetSourcePool (client) wires a source-IP rotation pool: the crafted-header source IP the client
// sends FROM is cycled/burned alongside the destination. flux stamps the source per packet, so a
// rotation is just an atomic swap — no socket rebind; the server follows the new source (it learns
// the peer from received frames). nil / single-endpoint = fixed source. Call before Run().
func (f *Flux) SetSourcePool(sp *PeerPool) {
	if !f.isClient {
		return
	}
	f.sp = sp
	// Seed the initial source so the client stamps SrcIPs[0] from the first packet (matching the pool's
	// cur=0), instead of the route-derived default until the first rotation. Called before Run(), so
	// learnPeer/tryHandshake's `if localIP==nil` guard then leaves this in place.
	if sp != nil {
		if ip := parseIP4(hostOnly(sp.current())); ip != nil {
			f.localIP.Store(&net.IPAddr{IP: ip})
		}
	}
}

// rotateSourceFlux points the client at the next source-pool IP and swaps the crafted-header source.
// No session reset is needed (the source is independent of the AEAD session); the server rebinds to
// the new source on the next authenticated frame. No-op when the pool did not move or the IP is not v4.
func (f *Flux) rotateSourceFlux(proactive bool) {
	if f.sp == nil {
		return
	}
	addr, moved := f.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := parseIP4(hostOnly(addr))
	if ip == nil {
		return
	}
	f.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("flux: rotated source to %s", addr)
	// Source swap keeps the same AEAD session (no re-handshake) -> no matching reconnect. Use event() not
	// down() so wasDown isn't armed (a phantom recovery), and carry the new source IP for the panel log.
	f.st.event("down", "src-rotate", "ip:"+addr)
}

// rotatePeerFlux points the client at the next pool endpoint (burn+advance, or a timed rotate) and
// clears the session so the next loop re-handshakes against the new destination. No-op when the pool
// did not move or the endpoint is not a valid IPv4 (flux is IPv4-only).
func (f *Flux) rotatePeerFlux(proactive bool) {
	if f.pp == nil {
		return
	}
	addr, moved := f.pp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := parseIP4(hostOnly(addr))
	if ip == nil {
		return
	}
	f.peer.Store(&net.IPAddr{IP: ip})
	f.session.Store(nil)
	f.ci.Store(nil)
	// Refresh the status descriptor to the NEW peer so "active" doesn't stay pinned to the dialed IP
	// SetStatusPath baked in — same "flux:<carrier> · <peer>" format (nil-safe when status is off).
	f.st.setActive("flux:" + f.carrier + " · " + ip.String())
	// Fresh staleness window + unproven mark for the jumped-to endpoint, so a proactive jump onto a dead
	// endpoint fails over within the dead window instead of stranding (clear mode). Mirrors rotatePeerUDP.
	f.lastRx.Store(time.Now().UnixNano())
	f.peerAnswered.Store(false)
	log.Printf("flux: rotated destination to %s", addr)
	f.st.down("peer-rotate", "ip:"+addr) // clears the session -> re-handshake -> reconnect pairs the down
}

// adoptPeerFlux re-points the client at the pool's CURRENT destination — used when an operator pin has
// just jumped the pool to a chosen endpoint — and clears the session so the next loop re-handshakes there.
func (f *Flux) adoptPeerFlux() {
	if f.pp == nil {
		return
	}
	ip := parseIP4(hostOnly(f.pp.current()))
	if ip == nil {
		return
	}
	f.peer.Store(&net.IPAddr{IP: ip})
	f.session.Store(nil)
	f.ci.Store(nil)
	// Refresh the status descriptor to the pinned peer so "active" tracks the current destination
	// (same "flux:<carrier> · <peer>" format as SetStatusPath; nil-safe when status is off).
	f.st.setActive("flux:" + f.carrier + " · " + ip.String())
	log.Printf("flux: pinned destination to %s", ip)
	f.st.down("peer-pin", "ip:"+ip.String()) // clears the session -> re-handshake -> reconnect pairs the down
}

// adoptSourceFlux swaps the crafted-header source to the pool's CURRENT source (an operator source pin).
// Like rotateSourceFlux it leaves the AEAD session intact — the source is stamped per packet.
func (f *Flux) adoptSourceFlux() {
	if f.sp == nil {
		return
	}
	ip := parseIP4(hostOnly(f.sp.current()))
	if ip == nil {
		return
	}
	f.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("flux: pinned source to %s", ip)
	f.st.event("down", "src-pin", "ip:"+ip.String()) // source pin: session survives, no reconnect (see rotateSourceFlux)
}

// ProbeAllNow retests every suspect/dead endpoint on both pools at once (the panel "probe now" control,
// delivered as SIGHUP). No-op unless pooled.
func (f *Flux) ProbeAllNow() {
	probeAllPools(f.pp, f.sp)
}

// pinPollLoop polls the pools' cmd files on a 1s ticker and applies any operator pin (re-pointing the
// live dataplane at the pinned endpoint via pollPins). Runs until Close.
func (f *Flux) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, f.closeCh, f.adoptPeerFlux, f.adoptSourceFlux)
}

func (f *Flux) clientLoop() {
	failN := 0
	rc := newRotationController(f.pp, f.sp)
	if rc.active() {
		go f.pinPollLoop(rc)
	}
	// Seed the staleness baseline NOW (clear mode). Without it, sessionStale() returns false while
	// lastRx==0, so a clear-mode failover-only pool whose first endpoint is dead never fires. Mirrors UDP.
	f.lastRx.Store(time.Now().UnixNano())
	for {
		if f.cryptoOn && f.sealer() != nil && f.sessionStale() {
			f.session.Store(nil)
			f.ci.Store(nil)
			log.Print("flux: no reply from the peer's session — re-handshaking (peer likely restarted)")
			f.st.down("stale", "flux") // precise reason for the panel log (nil-safe when off)
		}
		// Clear mode has no handshake whose failure would drive failover, so a dead pool endpoint would
		// otherwise strand the tunnel forever. Use receive-staleness (the peer pongs our pings). Mirrors UDP.
		if !f.cryptoOn && rc.active() && f.sessionStale() {
			rc.fail(f.rotatePeerFlux, f.rotateSourceFlux)
			f.lastRx.Store(time.Now().UnixNano()) // fresh window even if the pool couldn't move (single endpoint / source-only)
			f.peerAnswered.Store(false)           // stale -> the current endpoint is no longer proven answering
			f.st.down("stale", "flux")
		}
		if f.cryptoOn && f.sealer() == nil {
			f.sendInit()
			if failN++; rc.active() && failN >= peerFailThreshold {
				rc.fail(f.rotatePeerFlux, f.rotateSourceFlux) // burn+advance dest; walk source once dests cycle
				failN = 0
			}
		} else {
			// Heal transient burns on endpoints proving themselves. Clear mode has no handshake, so use
			// the data plane (peerAnswered), so a just-jumped-to endpoint's burn is never falsely cleared.
			if failN > 0 || (!f.cryptoOn && rc.active() && f.peerAnswered.Load()) {
				healEvents(f.st, rc)
			}
			failN = 0
			f.send(typePing, nil, f.peer.Load())
			rc.proactive(f.rotatePeerFlux, f.rotateSourceFlux, time.Now())
			if f.cryptoOn && f.sealer() == nil {
				// A proactive DESTINATION rotation just cleared the crypto session — loop back NOW to send
				// the re-handshake init immediately, instead of first sleeping the 1s retransmit interval
				// below, so the rotation gap is ~1 RTT rather than ~1s (matters for live streams). Clear
				// mode has no session/handshake so this never fires there; a duplicated init is harmless
				// (the server dedups via the init cache).
				continue
			}
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
		// Fresh handshake cycle (not a 1s retransmit): desync the DPI right before the init.
		f.sendFakes(peer)
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

// rotateWatcher refreshes the cached send-side shape every second (so carrierOut
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
