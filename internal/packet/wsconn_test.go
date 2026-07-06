package packet

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// End-to-end WebSocket carrier over a real loopback socket: client upgrade ↔ server
// upgrade, then a stream round-trip in both directions. Exercises masking (client
// masks, server does not) and the stream de-framing the connFramer relies on.
func TestWSConnRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvDone <- nil
			return
		}
		defer c.Close()
		r, err := wsServerHandshake(c, time.Now().Add(2*time.Second))
		if err != nil {
			srvDone <- nil
			return
		}
		ws := &wsConn{Conn: c, r: r, client: false}
		got := make([]byte, 5)
		if _, err := io.ReadFull(ws, got); err != nil {
			srvDone <- nil
			return
		}
		_, _ = ws.Write([]byte("PONG-back"))
		srvDone <- got
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := wsClientHandshake(c, "example.test", "/tunnel", time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	ws := &wsConn{Conn: c, r: r, client: true}
	if _, err := ws.Write([]byte("HELLO")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 9)
	if _, err := io.ReadFull(ws, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if got := <-srvDone; !bytes.Equal(got, []byte("HELLO")) {
		t.Fatalf("server got %q, want HELLO", got)
	}
	if !bytes.Equal(reply, []byte("PONG-back")) {
		t.Fatalf("client got %q, want PONG-back", reply)
	}
}

// A stream larger than one Read call must reassemble correctly (the connFramer does
// io.ReadFull for exact byte counts across frame boundaries).
func TestWSConnStreamsAcrossReads(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// Drive the framing directly (no handshake) — client writes, server reads.
	cw := &wsConn{Conn: a, r: bufio.NewReader(a), client: true}
	sr := &wsConn{Conn: b, r: bufio.NewReader(b), client: false}
	payload := bytes.Repeat([]byte("xy"), 5000) // 10000 bytes, forces 16-bit length
	go func() { _, _ = cw.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sr, got); err != nil {
		t.Fatalf("readfull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("stream corrupted across frame boundary")
	}
}

// A non-WebSocket request (a probe/scanner/browser) must get a 404 and errNotWS,
// so the port looks like an ordinary idle web endpoint, not a tunnel.
func TestWSServerRejectsNonWS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := wsServerHandshake(c, time.Now().Add(2*time.Second)); err != errNotWS {
			t.Errorf("expected errNotWS, got %v", err)
		}
	}()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp, _ := bufio.NewReader(c).ReadString('\n')
	if !bytes.Contains([]byte(resp), []byte("404")) {
		t.Fatalf("probe got %q, want 404", resp)
	}
}
