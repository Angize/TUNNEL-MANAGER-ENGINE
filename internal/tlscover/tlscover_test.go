package tlscover

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestCoverRoundTrip drives a Chrome-mimicking client against a self-signed
// server over real loopback TCP and passes bytes both ways through the TLS tunnel.
func TestCoverRoundTrip(t *testing.T) {
	cert, err := SelfSignedCert("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		c, err := ServerConn(raw, cert, time.Now().Add(5*time.Second))
		if err != nil {
			srvDone <- err
			return
		}
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		if !bytes.Equal(buf[:n], []byte("ping")) {
			srvDone <- errf("server got %q", buf[:n])
			return
		}
		_, err = c.Write([]byte("pong"))
		srvDone <- err
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := ClientConn(raw, "www.example.com", time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("pong")) {
		t.Fatalf("client read: %v got %q", err, buf[:n])
	}
	if err := <-srvDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func errf(f string, a ...any) error { return &te{f, a} }

type te struct {
	f string
	a []any
}

func (e *te) Error() string { return e.f }
