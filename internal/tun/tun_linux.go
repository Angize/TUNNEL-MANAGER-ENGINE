// Package tun opens and configures a Linux TUN device (raw L3 packets, no PI
// header). Address/MTU/up are applied by shelling out to `ip`, matching the
// node agent's philosophy of driving iproute2 rather than talking netlink
// directly. The device is non-persistent, so closing the fd removes it.
package tun

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	tunSetIff = 0x400454ca
	ifReqSize = 40
)

// Device is an open TUN interface. When gso is set it was opened with a
// virtio-net header and segmentation offload; Read then serves one L3 packet per
// call out of a queue filled by splitting the kernel's super-packets (see
// offload_linux.go), so callers keep the simple one-packet-per-Read contract.
type Device struct {
	f    *os.File
	fd   int // raw blocking fd for data-path I/O — bypasses Go's netpoller (see rawRead)
	Name string

	gso  bool
	rbuf []byte   // super-packet read buffer (vnet header + up to 64 KiB)
	q    [][]byte // segments not yet handed out; drained before the next read

	nSuper, nSeg atomic.Uint64 // GSO diagnostic: super-packets split and segments produced
}

// Open creates the TUN interface, assigns addr (CIDR, e.g. "10.200.0.1/24"),
// sets mtu and brings it up. name is a hint; the kernel-assigned name is
// returned in Device.Name. When gso is true the device is opened with a
// virtio-net header and TCP/UDP segmentation offload for higher bulk throughput.
func Open(name string, mtu int, addr string, gso bool) (*Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	flags := uint16(iffTun | iffNoPI)
	if gso {
		flags |= iffVnetHdr
	}
	var ifr [ifReqSize]byte
	copy(ifr[:15], name) // leave room for NUL terminator
	binary.LittleEndian.PutUint16(ifr[16:18], flags)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIff, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	real := strings.TrimRight(string(ifr[:16]), "\x00")

	if gso {
		off := uintptr(tunFCSUM | tunFTSO4 | tunFTSO6)
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetOffload, off); errno != 0 {
			f.Close()
			return nil, fmt.Errorf("TUNSETOFFLOAD (gso): %w", errno)
		}
	}

	d := &Device{f: f, fd: int(f.Fd()), Name: real, gso: gso}
	if gso {
		d.rbuf = make([]byte, vnetHdrLen+65535)
	}
	if err := ipCmd("link", "set", "dev", real, "mtu", strconv.Itoa(mtu)); err != nil {
		d.Close()
		return nil, err
	}
	if err := ipCmd("addr", "add", addr, "dev", real); err != nil {
		d.Close()
		return nil, err
	}
	if err := ipCmd("link", "set", "dev", real, "up"); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// rawRead/rawWrite do blocking TUN I/O with a plain syscall, DELIBERATELY bypassing os.File and
// Go's netpoller. A dependency's package-init can bring the netpoller up before main() opens the
// TUN (kcp-go's SystemTimedSched starts goroutines at init); the TUN fd can then inherit a poisoned
// pollDesc from a transient regular-file fd that failed EPOLL_CTL_ADD (EPERM), and os.File.Read
// returns "not pollable", killing the data plane on EVERY transport. The TUN is opened blocking
// (no O_NONBLOCK; f.Fd() keeps it blocking), so a raw syscall.Read/Write always works regardless of
// init ordering. Same approach as wireguard-go. EINTR is retried; the fd lifetime is tied to d.f.
func rawRead(fd int, p []byte) (int, error) {
	for {
		n, err := syscall.Read(fd, p)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

func rawWrite(fd int, p []byte) (int, error) {
	for {
		n, err := syscall.Write(fd, p)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

// rd/wr are the data-path I/O. The production device (Open) has a real fd and uses the raw,
// netpoller-free path above; the test-only FromFile device sets fd<0 and falls back to os.File
// (its socketpair stand-in is pollable and never hits the poisoned-pollDesc problem).
func (d *Device) rd(p []byte) (int, error) {
	if d.fd >= 0 {
		return rawRead(d.fd, p)
	}
	return d.f.Read(p)
}

func (d *Device) wr(p []byte) (int, error) {
	if d.fd >= 0 {
		return rawWrite(d.fd, p)
	}
	return d.f.Write(p)
}

// Read returns one L3 packet into buf. With GSO enabled it serves segments from
// the queue, refilling it by reading and splitting one kernel super-packet.
func (d *Device) Read(buf []byte) (int, error) {
	if !d.gso {
		return d.rd(buf)
	}
	for len(d.q) == 0 {
		segs, err := d.readGSO()
		if err != nil {
			return 0, err
		}
		d.q = segs
	}
	n := copy(buf, d.q[0])
	d.q = d.q[1:]
	return n, nil
}

// readGSO reads one virtio super-packet and returns its L3 segments (one element
// for a non-GSO packet). A runt read returns no segments so Read retries.
func (d *Device) readGSO() ([][]byte, error) {
	n, err := d.rd(d.rbuf)
	if err != nil {
		return nil, err
	}
	if n <= vnetHdrLen {
		return nil, nil
	}
	flags := d.rbuf[0]
	gsoType := int(d.rbuf[1])
	gsoSize := int(binary.LittleEndian.Uint16(d.rbuf[4:6]))
	pkt := d.rbuf[vnetHdrLen:n]
	if gsoType&^gsoECN == gsoNone {
		if flags&vnetNeedsCsum != 0 {
			finalizeCsum(pkt)
		}
		return [][]byte{pkt}, nil
	}
	segs := splitGSO(pkt, gsoSize, gsoType)
	if len(segs) > 1 {
		d.nSuper.Add(1)
		d.nSeg.Add(uint64(len(segs)))
	}
	return segs, nil
}

// Write injects one L3 packet. With GSO the kernel expects a virtio-net header
// prefix; a zero header means "one complete packet, checksums done".
func (d *Device) Write(pkt []byte) (int, error) {
	if !d.gso {
		return d.wr(pkt)
	}
	out := make([]byte, vnetHdrLen+len(pkt))
	copy(out[vnetHdrLen:], pkt)
	n, err := d.wr(out)
	if n -= vnetHdrLen; n < 0 {
		n = 0
	}
	return n, err
}

// Close removes the interface (non-persistent).
func (d *Device) Close() error {
	if n := d.nSuper.Load(); d.gso && n > 0 {
		fmt.Printf("tun %s: gso split %d super-packets into %d segments\n", d.Name, n, d.nSeg.Load())
	}
	return d.f.Close()
}

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
