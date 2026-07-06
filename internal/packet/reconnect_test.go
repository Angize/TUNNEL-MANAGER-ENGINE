package packet

import (
	"bytes"
	"testing"
	"time"
)

// TestUDPReHandshakeOnReconnect proves a restarted client (fresh ephemeral) is
// re-handshaked by a still-running server and the tunnel recovers — the path that
// used to rely on the replay guard blindly adopting any new session.
func TestUDPReHandshakeOnReconnect(t *testing.T) {
	const psk = "reconnect-psk-abcdefghijklmnop"
	const cipher = "chacha20-poly1305"
	srvDev, srvCtrl := tunPair(t, "rsrv")
	addr := freeUDPPort(t)
	srv, err := Listen(addr, srvDev, time.Second, true, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	send := func(tag string) {
		cliDev, cliCtrl := tunPair(t, tag)
		cli, err := Dial(addr, cliDev, time.Second, true, true, psk, cipher, false, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		go cli.Run()
		time.Sleep(300 * time.Millisecond) // let the handshake complete
		pkt := bytes.Repeat([]byte{0x77}, 180)
		if _, err := cliCtrl.Write(pkt); err != nil {
			t.Fatalf("%s inject: %v", tag, err)
		}
		if got := readWithTimeout(t, srvCtrl, tag); !bytes.Equal(got, pkt) {
			t.Fatalf("%s: payload did not traverse the tunnel", tag)
		}
		cli.Close()
		cliDev.Close()
		cliCtrl.Close()
		time.Sleep(100 * time.Millisecond)
	}

	send("cli-first")  // initial handshake + data
	send("cli-second") // NEW client, NEW ephemeral -> server must re-handshake
}
