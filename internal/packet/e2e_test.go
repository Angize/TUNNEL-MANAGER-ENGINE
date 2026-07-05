package packet

import (
	"bytes"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/tun"
)

// tunPair returns a Device backed by one end of a unix datagram socketpair and
// the control file for the other end: write to ctrl -> dev.Read returns it
// (a packet "leaving" the app), and dev.Write -> ctrl.Read (a packet delivered
// to the app). SOCK_DGRAM preserves the one-packet-per-read TUN semantics.
func tunPair(t *testing.T, name string) (*tun.Device, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	dev := tun.FromFile(os.NewFile(uintptr(fds[0]), name+"-dev"), name)
	ctrl := os.NewFile(uintptr(fds[1]), name+"-ctrl")
	t.Cleanup(func() { dev.Close(); ctrl.Close() })
	return dev, ctrl
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func readWithTimeout(t *testing.T, ctrl *os.File, what string) []byte {
	t.Helper()
	type res struct {
		b []byte
		n int
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 2048)
		n, _ := ctrl.Read(buf)
		ch <- res{buf, n}
	}()
	select {
	case r := <-ch:
		if r.n <= 0 {
			t.Fatalf("%s: empty read", what)
		}
		return r.b[:r.n]
	case <-time.After(4 * time.Second):
		t.Fatalf("%s: timed out — packet never traversed the tunnel", what)
		return nil
	}
}

type carrier interface {
	Run() error
	Close() error
}

// runTunnel drives a full server<->client bip tunnel over a real socket for the
// given transport/obfs, injecting a packet each way and asserting it arrives
// intact — exercising seal/open, counter nonce, anti-replay, peer learning, and
// (tcp) handshake, the paths a live node runs.
func runTunnel(t *testing.T, transport string, obfs bool) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	sSealer, _ := crypto.NewSealer("aes-256-gcm", psk)
	cSealer, _ := crypto.NewSealer("aes-256-gcm", psk)
	srvDev, srvCtrl := tunPair(t, "srv")
	cliDev, cliCtrl := tunPair(t, "cli")
	ka := 1 * time.Second

	var srv, cli carrier
	var err error
	if transport == "tcp" {
		addr := freeTCPPort(t)
		srv, err = ListenTCP(addr, srvDev, sSealer, ka, obfs, psk)
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		cli, err = DialTCP(addr, cliDev, cSealer, ka, obfs, psk)
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
	} else {
		addr := freeUDPPort(t)
		srv, err = Listen(addr, srvDev, sSealer, ka, obfs)
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		cli, err = Dial(addr, cliDev, cSealer, ka, obfs)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(300 * time.Millisecond)

	pkt1 := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt1) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}

	pkt2 := bytes.Repeat([]byte{0x5A}, 500)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client payload mismatch: got %d bytes", len(got))
	}

	pkt3 := bytes.Repeat([]byte{0x33}, 120)
	if _, err := cliCtrl.Write(pkt3); err != nil {
		t.Fatalf("inject client->server #2: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server #2"); !bytes.Equal(got, pkt3) {
		t.Fatalf("client->server #2 payload mismatch")
	}
}

func TestTunnelUDP(t *testing.T)     { runTunnel(t, "udp", false) }
func TestTunnelUDPObfs(t *testing.T) { runTunnel(t, "udp", true) }
func TestTunnelTCP(t *testing.T)     { runTunnel(t, "tcp", false) }
func TestTunnelTCPObfs(t *testing.T) { runTunnel(t, "tcp", true) }
