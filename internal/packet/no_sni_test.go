package packet

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// helloCapConn records the client's first write (the TLS ClientHello) and then fails every read,
// so a handshake driven through it aborts right after emitting the ClientHello — enough to inspect
// what SNI, if any, actually went on the wire.
type helloCapConn struct {
	hello []byte
	wrote bool
}

func (c *helloCapConn) Write(p []byte) (int, error) {
	if !c.wrote {
		c.hello = append(c.hello, p...)
		c.wrote = true
	}
	return len(p), nil
}
func (c *helloCapConn) Read([]byte) (int, error)         { return 0, errors.New("no server") }
func (c *helloCapConn) Close() error                     { return nil }
func (c *helloCapConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1} }
func (c *helloCapConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443} }
func (c *helloCapConn) SetDeadline(time.Time) error      { return nil }
func (c *helloCapConn) SetReadDeadline(time.Time) error  { return nil }
func (c *helloCapConn) SetWriteDeadline(time.Time) error { return nil }

func TestTLSToEdgeNoSNIOmitsHostname(t *testing.T) {
	const host = "cdn.spcefastpro.org"

	// Default (SNI sent): the cleartext hostname must appear in the ClientHello.
	b := &TCP{isClient: true, ws: true, wsTLS: true}
	cc := &helloCapConn{}
	_, _ = b.tlsToEdge(cc, "1.2.3.4:443", host, nil, false) // handshake fails after the ClientHello; we only inspect it
	if !bytes.Contains(cc.hello, []byte(host)) {
		t.Fatalf("default handshake should carry the cleartext SNI %q on the wire", host)
	}

	// no-SNI: SetNoSNI must enable it, and the hostname must NOT appear anywhere in the ClientHello.
	b = &TCP{isClient: true, ws: true, wsTLS: true}
	b.SetNoSNI(true)
	if !b.wsNoSNI {
		t.Fatal("SetNoSNI did not enable no-SNI on a valid wss client")
	}
	cc = &helloCapConn{}
	_, _ = b.tlsToEdge(cc, "1.2.3.4:443", host, nil, false)
	if bytes.Contains(cc.hello, []byte(host)) {
		t.Fatal("no-SNI handshake must not put the hostname on the wire")
	}
}

func TestSetNoSNIGating(t *testing.T) {
	// Not a client -> ignored.
	b := &TCP{isClient: false, ws: true, wsTLS: true}
	b.SetNoSNI(true)
	if b.wsNoSNI {
		t.Error("SetNoSNI must be a no-op on the server")
	}
	// Client but not ws -> ignored.
	b = &TCP{isClient: true, ws: false, wsTLS: true}
	b.SetNoSNI(true)
	if b.wsNoSNI {
		t.Error("SetNoSNI must be a no-op on a non-ws carrier")
	}
	// Client + ws but not wss -> ignored (there is no ClientHello to strip).
	b = &TCP{isClient: true, ws: true, wsTLS: false}
	b.SetNoSNI(true)
	if b.wsNoSNI {
		t.Error("SetNoSNI must be a no-op without ws_tls")
	}
	// off -> ignored.
	b = &TCP{isClient: true, ws: true, wsTLS: true}
	b.SetNoSNI(false)
	if b.wsNoSNI {
		t.Error("SetNoSNI(false) must not enable no-SNI")
	}
}
