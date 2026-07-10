//go:build linux

// L2 packet injection: send fully hand-crafted IPv4 packets to a peer via an AF_PACKET
// SOCK_RAW socket, so the kernel does NOT touch the L3 header. This exists because an
// IP_HDRINCL raw socket ALWAYS recomputes the IPv4 header checksum (raw(7)), which silently
// "repairs" a deliberately-bad checksum before it hits the wire — so a bad-checksum desync
// decoy is a no-op over IP_HDRINCL. AF_PACKET hands the frame to the driver verbatim, so a
// forged checksum (or, later, a hand-built TCP segment for the tcp-inject carrier) survives.
//
// To send at L2 we need the Ethernet header the kernel would use for the peer: the egress
// interface (its ifindex + MAC) and the next-hop MAC. We learn both from the kernel's own
// routing + neighbour tables (/proc/net/route + /proc/net/arp) rather than re-implementing
// routing — the next hop is the gateway for an off-subnet peer, or the peer itself on-link.
// Resolution is lazy and cached: the first send after the neighbour is warm (a gateway MAC
// is essentially always cached) succeeds; a still-cold neighbour just fails that best-effort
// decoy.
package packet

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// l2route is the Ethernet framing for reaching the peer: the egress interface and the
// source (our NIC) + destination (next-hop) MACs.
type l2route struct {
	ifindex int
	src     [6]byte
	dst     [6]byte
}

// l2inject injects raw IPv4 packets to a peer over AF_PACKET. The route is resolved once and
// cached (rt); until the next hop is resolvable, send() returns an error and transmits nothing.
type l2inject struct {
	mu   sync.Mutex
	fd   int
	peer net.IP
	rt   *l2route
}

// newL2Inject opens the AF_PACKET SOCK_RAW send socket. Protocol 0 means it receives nothing
// (we only transmit), so it never floods its RX queue. It needs CAP_NET_RAW, which the raw/
// flux carriers already hold.
func newL2Inject(peer net.IP) (*l2inject, error) {
	p := peer.To4()
	if p == nil {
		return nil, fmt.Errorf("l2: peer %v is not IPv4", peer)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, err
	}
	return &l2inject{fd: fd, peer: p}, nil
}

func (l *l2inject) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fd >= 0 {
		syscall.Close(l.fd)
		l.fd = -1
	}
}

// send injects one IPv4 packet (full IP header + payload) toward the peer, prepending the
// resolved Ethernet header. The route is resolved lazily on first use and cached. Returns an
// error (sending nothing) when the socket is closed or the next hop isn't resolvable yet.
func (l *l2inject) send(ipPkt []byte) error {
	l.mu.Lock()
	if l.fd < 0 {
		l.mu.Unlock()
		return fmt.Errorf("l2: injector closed")
	}
	if l.rt == nil {
		rt, err := resolveL2(l.peer)
		if err != nil {
			l.mu.Unlock()
			return err
		}
		l.rt = rt
	}
	fd, rt := l.fd, l.rt
	l.mu.Unlock()

	frame := make([]byte, 14+len(ipPkt))
	copy(frame[0:6], rt.dst[:])
	copy(frame[6:12], rt.src[:])
	binary.BigEndian.PutUint16(frame[12:14], ethPIP) // 0x0800 IPv4
	copy(frame[14:], ipPkt)

	sa := &syscall.SockaddrLinklayer{Ifindex: rt.ifindex, Halen: 6}
	copy(sa.Addr[:6], rt.dst[:])
	return syscall.Sendto(fd, frame, 0, sa)
}

// resolveL2 finds the egress interface and next-hop MAC for peer from the kernel routing and
// neighbour tables. next hop = the route's gateway (off-subnet) or the peer itself (on-link).
func resolveL2(peer net.IP) (*l2route, error) {
	ifname, gw, err := routeFor(peer)
	if err != nil {
		return nil, err
	}
	nextHop := gw
	if nextHop == nil {
		nextHop = peer // on-link: the peer is its own next hop
	}
	dst, err := neighMAC(nextHop, ifname)
	if err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("l2: %s has no Ethernet MAC", ifname)
	}
	rt := &l2route{ifindex: iface.Index, dst: dst}
	copy(rt.src[:], iface.HardwareAddr)
	return rt, nil
}

// routeFor reads /proc/net/route and returns the egress interface and gateway for the
// longest-prefix route matching peer (gw is nil for an on-link route). The Destination/
// Gateway/Mask columns are the 32-bit address printed as native-endian hex, which matches
// reading peer with binary.LittleEndian on our little-endian targets.
func routeFor(peer net.IP) (ifname string, gw net.IP, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	p4 := binary.LittleEndian.Uint32(peer.To4())
	best := -1
	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fld := strings.Fields(sc.Text())
		if len(fld) < 8 {
			continue
		}
		dest, e1 := strconv.ParseUint(fld[1], 16, 32)
		mask, e2 := strconv.ParseUint(fld[7], 16, 32)
		if e1 != nil || e2 != nil {
			continue
		}
		m := uint32(mask)
		if p4&m != uint32(dest)&m {
			continue // this route does not cover the peer
		}
		if ones := bits.OnesCount32(m); ones > best {
			best = ones
			ifname = fld[0]
			if g, _ := strconv.ParseUint(fld[2], 16, 32); g != 0 {
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], uint32(g))
				gw = net.IP(b[:]).To4()
			} else {
				gw = nil
			}
		}
	}
	if best < 0 {
		return "", nil, fmt.Errorf("l2: no route to %s", peer)
	}
	return ifname, gw, nil
}

// neighMAC reads /proc/net/arp and returns the resolved MAC for ip on ifname. Incomplete
// entries (ATF_COM/0x2 flag clear) are skipped — a cold neighbour yields an error so the
// caller degrades that decoy rather than sending to a zero MAC.
func neighMAC(ip net.IP, ifname string) (mac [6]byte, err error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return mac, err
	}
	defer f.Close()
	want := ip.String()
	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fld := strings.Fields(sc.Text()) // IP HWtype Flags HWaddr Mask Device
		if len(fld) < 6 || fld[0] != want {
			continue
		}
		if fld[5] != ifname { // a peer IP could appear on several devices
			continue
		}
		flags, _ := strconv.ParseUint(fld[2], 0, 32)
		if flags&0x2 == 0 { // ATF_COM: only a completed entry has a usable MAC
			continue
		}
		hw, e := net.ParseMAC(fld[3])
		if e != nil || len(hw) != 6 {
			continue
		}
		copy(mac[:], hw)
		return mac, nil
	}
	return mac, fmt.Errorf("l2: neighbour %s on %s not resolved", want, ifname)
}
