package packet

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// waitFor polls cond until it holds or the deadline elapses (t.Fatal otherwise). Used to await
// asynchronous carrier transitions (connect / promote) driven by background goroutines.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: condition not met within %v", what, d)
}

// dialWSClient opens ONE authenticated ws client carrier to a ListenWS server (crypto on, obfs
// off) using the same steps the real client runs — TCP dial, WebSocket upgrade, ephemeral
// handshake, then a prime ping — and drains the server's pong so later reads see only downstream
// frames. It returns the established connFramer for the test to write/read frames on directly.
func dialWSClient(t *testing.T, addr, psk, cipher string) *connFramer {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r, err := wsClientHandshake(raw, "front.example", "/", time.Now().Add(5*time.Second))
	if err != nil {
		raw.Close()
		t.Fatalf("ws upgrade: %v", err)
	}
	wc := &wsConn{Conn: raw, r: r, client: true}
	cb := &TCP{cryptoOn: true, cipher: cipher, psk: psk} // just to reuse newFramer + clientHandshake
	cf := cb.newFramer(wc)
	wc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := cb.clientHandshake(cf); err != nil {
		raw.Close()
		t.Fatalf("client handshake: %v", err)
	}
	wc.SetReadDeadline(time.Time{})
	if err := cf.writeFrame(typePing, nil); err != nil { // prime + authenticate to the server
		raw.Close()
		t.Fatalf("prime ping: %v", err)
	}
	cf.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if typ, _, _, _, err := cf.readFrame(); err != nil || typ != typePong { // drain prime pong
		raw.Close()
		t.Fatalf("prime pong: typ=%d err=%v", typ, err)
	}
	t.Cleanup(func() { raw.Close() })
	return cf
}

// readFrameT reads one frame under a timeout and returns its type + a copy of the payload.
func readFrameT(t *testing.T, cf *connFramer, what string) (byte, []byte) {
	t.Helper()
	cf.conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	typ, _, _, pt, err := cf.readFrame()
	if err != nil {
		t.Fatalf("%s: readFrame: %v", what, err)
	}
	return typ, append([]byte(nil), pt...)
}

// TestServerDownstreamFollowsData proves the server-side invariant the warm-standby feature
// depends on, without any client machinery: two concurrent authenticated connections A and B,
// the server keeps BOTH, and its TUN->client downstream target follows the connection that most
// recently sent a DATA frame (never a ping, never merely the newest connection). It also proves a
// single connection behaves exactly as before, and that closing the old downstream does not
// interrupt delivery on the survivor (no re-handshake — the same session keeps decoding).
func TestServerDownstreamFollowsData(t *testing.T) {
	const psk = "downstream-follows-data-psk-123456"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "sdf")
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, time.Second, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(100 * time.Millisecond) // let the listener come up

	// --- single connection: behaves exactly as before ---
	a := dialWSClient(t, addr, psk, cipher)
	waitFor(t, 4*time.Second, "A published as downstream", func() bool { return srv.cur.Load() != nil })

	pA := bytes.Repeat([]byte{0x11}, 150)
	if err := a.writeFrame(typeData, pA); err != nil {
		t.Fatalf("A data: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "A->server data"); !bytes.Equal(got, pA) {
		t.Fatalf("A->server payload mismatch")
	}
	d1 := bytes.Repeat([]byte{0x21}, 250)
	if _, err := srvCtrl.Write(d1); err != nil {
		t.Fatalf("inject downstream d1: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream on A"); typ != typeData || !bytes.Equal(pt, d1) {
		t.Fatalf("downstream d1 not delivered on A (typ=%d)", typ)
	}

	// --- a second connection connects but must NOT steal downstream (it only pinged) ---
	b := dialWSClient(t, addr, psk, cipher)
	d2 := bytes.Repeat([]byte{0x22}, 260)
	if _, err := srvCtrl.Write(d2); err != nil {
		t.Fatalf("inject downstream d2: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream stays on A after B connects"); typ != typeData || !bytes.Equal(pt, d2) {
		t.Fatalf("downstream must stay on A when B only connected (typ=%d)", typ)
	}

	// --- a PING on B must NOT move downstream ---
	if err := b.writeFrame(typePing, nil); err != nil {
		t.Fatalf("B ping: %v", err)
	}
	if typ, _ := readFrameT(t, b, "B pong"); typ != typePong {
		t.Fatalf("B ping should be answered by a pong, got typ=%d", typ)
	}
	d3 := bytes.Repeat([]byte{0x23}, 270)
	if _, err := srvCtrl.Write(d3); err != nil {
		t.Fatalf("inject downstream d3: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream stays on A after B ping"); typ != typeData || !bytes.Equal(pt, d3) {
		t.Fatalf("a ping must not steal downstream (typ=%d)", typ)
	}

	// --- DATA on B flips downstream to B within one frame ---
	pB := bytes.Repeat([]byte{0x31}, 160)
	if err := b.writeFrame(typeData, pB); err != nil {
		t.Fatalf("B data: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "B->server data"); !bytes.Equal(got, pB) {
		t.Fatalf("B->server payload mismatch")
	}
	d4 := bytes.Repeat([]byte{0x24}, 280)
	if _, err := srvCtrl.Write(d4); err != nil {
		t.Fatalf("inject downstream d4: %v", err)
	}
	if typ, pt := readFrameT(t, b, "downstream flipped to B"); typ != typeData || !bytes.Equal(pt, d4) {
		t.Fatalf("downstream must follow B's data (typ=%d)", typ)
	}

	// --- closing A does NOT interrupt delivery on B (and B never re-handshook) ---
	a.conn.Close()
	time.Sleep(150 * time.Millisecond)
	d5 := bytes.Repeat([]byte{0x25}, 290)
	if _, err := srvCtrl.Write(d5); err != nil {
		t.Fatalf("inject downstream d5: %v", err)
	}
	if typ, pt := readFrameT(t, b, "delivery continues on B after A closes"); typ != typeData || !bytes.Equal(pt, d5) {
		t.Fatalf("closing A must not disturb B (typ=%d)", typ)
	}
}

// TestWarmStandbyFailover drives the full make-before-break client against a real in-process
// ListenWS server over a two-edge pool (two SNIs fronting one origin). It asserts that the client
// warms a standby, that traffic flows both ways over the active, and that killing the active
// promotes the ALREADY-WARM standby (proven by framer pointer identity — not a fresh dial) with
// data continuing to flow both directions and no re-handshake.
func TestWarmStandbyFailover(t *testing.T) {
	const psk = "warm-standby-psk-abcdefghijklmnop"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "wsrv")
	cliDev, cliCtrl := tunPair(t, "wcli")
	ka := time.Second
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, ka, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	// One edge IP (the in-process server) with two SNIs, so the active and the warm standby open
	// two DISTINCT connections to the same origin — modelling two CDN edges fronting one server.
	// wsTLS is off because the in-process ListenWS is plain (a real pool is wss).
	pool := newWSPool([]string{addr}, snis("front-a", "front-b"), false, "")
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: cipher, keepalive: ka, psk: psk,
		ws: true, wsTLS: false, pool: pool, warmStandby: true,
		idle: idleFor(ka), isClient: true, addr: "pool", closeCh: make(chan struct{})}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	// Both the active and the warm standby must come up.
	waitFor(t, 5*time.Second, "active up", func() bool { return cli.cur.Load() != nil })
	waitFor(t, 5*time.Second, "warm standby up", func() bool { return cli.standby.Load() != nil })

	// client -> server over the active.
	pkt1 := bytes.Repeat([]byte{0xA1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject pkt1: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server (active)"); !bytes.Equal(got, pkt1) {
		t.Fatalf("pkt1 mismatch")
	}
	// server -> client over the active (downstream followed the client's pkt1 above).
	pkt2 := bytes.Repeat([]byte{0xB2}, 300)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject pkt2: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client (active)"); !bytes.Equal(got, pkt2) {
		t.Fatalf("pkt2 mismatch")
	}

	// Capture the warm standby framer, then KILL the active carrier.
	oldStandby := cli.standby.Load()
	if oldStandby == nil {
		t.Fatal("expected a warm standby before killing the active")
	}
	active := cli.cur.Load()
	active.conn.Close() // simulate the active carrier failing

	// The PRE-WARMED standby must be promoted (exact same framer), not a fresh dial.
	waitFor(t, 5*time.Second, "standby promoted to active", func() bool { return cli.cur.Load() == oldStandby })

	// Traffic continues with no rebuild: client -> server flips the server downstream onto the
	// promoted carrier, then server -> client is delivered over it.
	pkt3 := bytes.Repeat([]byte{0xC3}, 180)
	if _, err := cliCtrl.Write(pkt3); err != nil {
		t.Fatalf("inject pkt3: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server (promoted)"); !bytes.Equal(got, pkt3) {
		t.Fatalf("pkt3 mismatch after promotion")
	}
	pkt4 := bytes.Repeat([]byte{0xD4}, 320)
	if _, err := srvCtrl.Write(pkt4); err != nil {
		t.Fatalf("inject pkt4: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client (promoted)"); !bytes.Equal(got, pkt4) {
		t.Fatalf("pkt4 mismatch after promotion")
	}

	// A fresh standby must be re-established in the background after the promotion.
	waitFor(t, 5*time.Second, "fresh standby rebuilt", func() bool {
		sb := cli.standby.Load()
		return sb != nil && sb != oldStandby
	})
}
