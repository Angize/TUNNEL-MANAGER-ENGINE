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
	"syscall"
	"unsafe"
)

const (
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	tunSetIff = 0x400454ca
	ifReqSize = 40
)

// Device is an open TUN interface.
type Device struct {
	f    *os.File
	Name string
}

// Open creates the TUN interface, assigns addr (CIDR, e.g. "10.200.0.1/24"),
// sets mtu and brings it up. name is a hint; the kernel-assigned name is
// returned in Device.Name.
func Open(name string, mtu int, addr string) (*Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var ifr [ifReqSize]byte
	copy(ifr[:15], name) // leave room for NUL terminator
	binary.LittleEndian.PutUint16(ifr[16:18], iffTun|iffNoPI)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIff, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	real := strings.TrimRight(string(ifr[:16]), "\x00")

	d := &Device{f: f, Name: real}
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

// Read returns one L3 packet into buf.
func (d *Device) Read(buf []byte) (int, error) { return d.f.Read(buf) }

// Write injects one L3 packet.
func (d *Device) Write(pkt []byte) (int, error) { return d.f.Write(pkt) }

// Close removes the interface (non-persistent).
func (d *Device) Close() error { return d.f.Close() }

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
