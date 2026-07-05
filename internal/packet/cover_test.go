package packet

import (
	"bytes"
	"testing"
	"time"
)

// TestTunnelTCPCover drives a full bip TCP tunnel wrapped in the TLS cover, with
// the ephemeral handshake + obfs framing running INSIDE the TLS session, and
// asserts a packet traverses it both ways.
func TestTunnelTCPCover(t *testing.T) {
	const psk = "cover-e2e-psk-abcdefghijklmnop"
	const cipher = "chacha20-poly1305"
	const sni = "www.microsoft.com"
	srvDev, srvCtrl := tunPair(t, "csrv")
	cliDev, cliCtrl := tunPair(t, "ccli")
	addr := freeTCPPort(t)

	srv, err := ListenTCP(addr, srvDev, time.Second, true, true, psk, cipher, true, sni)
	if err != nil {
		t.Fatalf("ListenTCP+cover: %v", err)
	}
	cli, err := DialTCP(addr, cliDev, time.Second, true, true, psk, cipher, true, sni)
	if err != nil {
		t.Fatalf("DialTCP+cover: %v", err)
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(500 * time.Millisecond) // TLS handshake + bip handshake

	pkt := bytes.Repeat([]byte{0xEE}, 300)
	if _, err := cliCtrl.Write(pkt); err != nil {
		t.Fatal(err)
	}
	if got := readWithTimeout(t, srvCtrl, "cover client->server"); !bytes.Equal(got, pkt) {
		t.Fatalf("client->server through TLS cover failed")
	}
	pkt2 := bytes.Repeat([]byte{0x2A}, 250)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatal(err)
	}
	if got := readWithTimeout(t, cliCtrl, "cover server->client"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client through TLS cover failed")
	}
}
