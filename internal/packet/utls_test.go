package packet

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// chWriteConn records everything written (the TLS ClientHello) and fails reads, so a handshake
// driven through it aborts right after emitting the ClientHello — enough to inspect what went on
// the wire.
type chWriteConn struct{ hello []byte }

func (c *chWriteConn) Write(p []byte) (int, error) {
	c.hello = append(c.hello, p...)
	return len(p), nil
}
func (c *chWriteConn) Read([]byte) (int, error)         { return 0, errors.New("no server") }
func (c *chWriteConn) Close() error                     { return nil }
func (c *chWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1} }
func (c *chWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443} }
func (c *chWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *chWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chWriteConn) SetWriteDeadline(time.Time) error { return nil }

// greaseCount counts 16-bit GREASE values (RFC 8701: two identical bytes whose low nibble is 0xa,
// e.g. 0x0a0a, 0x1a1a … 0xfafa) in the ClientHello. Go's crypto/tls never emits GREASE; uTLS's
// Chrome fingerprint sprinkles it through the cipher list, extensions and groups — so a nonzero
// count is a reliable "this is the Chrome fingerprint, not Go" signal.
func greaseCount(b []byte) int {
	n := 0
	for i := 0; i+1 < len(b); i++ {
		if b[i] == b[i+1] && b[i]&0x0f == 0x0a {
			n++
		}
	}
	return n
}

func TestTLSToEdgeUsesChromeFingerprintALPNh1(t *testing.T) {
	cc := &chWriteConn{}
	b := &TCP{isClient: true, ws: true, wsTLS: true}
	// Handshake fails (no server) right after the ClientHello; we only inspect what was sent.
	_, _ = b.tlsToEdge(cc, "1.2.3.4:443", "cdn.example.com", nil, false)
	if len(cc.hello) == 0 {
		t.Fatal("no ClientHello was written")
	}
	// Chrome fingerprint: GREASE must be present (Go's crypto/tls never emits any).
	if g := greaseCount(cc.hello); g < 2 {
		t.Fatalf("expected the Chrome fingerprint (multiple GREASE values), got %d — looks like Go's crypto/tls", g)
	}
	// ALPN must offer http/1.1 (so the WebSocket upgrade works)...
	if !bytes.Contains(cc.hello, []byte("http/1.1")) {
		t.Fatal("ClientHello must advertise http/1.1 in ALPN")
	}
	// ...and the ALPN list must NOT offer h2, else the edge could pick HTTP/2 and break our raw
	// HTTP/1.1 WebSocket upgrade. In Chrome's ALPN the h2 vector is immediately followed by the
	// http/1.1 vector ([0x02 h 2][0x08 h t t p / 1 . 1]); matching that combined run keys on the
	// ALPN specifically and is not fooled by the ApplicationSettings (ALPS) extension, which
	// legitimately still carries a bare "h2" ([0x02 h 2]) as part of the authentic Chrome
	// fingerprint (ALPS does not drive protocol negotiation — only ALPN does).
	alpnH2 := []byte{0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	if bytes.Contains(cc.hello, alpnH2) {
		t.Fatal("ALPN must not offer h2 (would break the HTTP/1.1 WebSocket upgrade)")
	}
	// The real hostname is present (no ECH here), i.e. SNI is sent as usual when ECH is absent.
	if !bytes.Contains(cc.hello, []byte("cdn.example.com")) {
		t.Fatal("without ECH the SNI should carry the hostname")
	}
}

// The grpc/stream xhttp carrier passes alpn=nil to uEdgeHandshake so the ClientHello keeps Chrome's
// h2 (the edge must negotiate HTTP/2). Verify the emitted hello is still Chrome (GREASE) and offers
// h2 in ALPN.
func TestUEdgeHandshakeH2ALPN(t *testing.T) {
	cc := &chWriteConn{}
	_, _ = uEdgeHandshake(cc, "cdn.example.com", nil, nil) // fails on read; inspect the ClientHello
	if len(cc.hello) == 0 {
		t.Fatal("no ClientHello was written")
	}
	if greaseCount(cc.hello) < 2 {
		t.Fatal("expected the Chrome fingerprint (GREASE) on the grpc/h2 path")
	}
	// Chrome's ALPN vector: the h2 entry immediately followed by http/1.1.
	alpnH2 := []byte{0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	if !bytes.Contains(cc.hello, alpnH2) {
		t.Fatal("grpc/h2 path must offer h2 in ALPN so the edge negotiates HTTP/2")
	}
}

// chromeSpec must build against the current pinned Chrome parrot (guards a uTLS bump that might
// drop the version or the ALPN extension) and honor the ALPN override / passthrough.
func TestChromeSpecALPN(t *testing.T) {
	// Override to http/1.1 only.
	h1, err := chromeSpec([]string{"http/1.1"})
	if err != nil {
		t.Fatalf("chromeSpec(http/1.1) failed on the pinned Chrome parrot: %v", err)
	}
	assertALPN(t, h1, []string{"http/1.1"})
	// nil keeps Chrome's default [h2, http/1.1] for the grpc carrier.
	h2, err := chromeSpec(nil)
	if err != nil {
		t.Fatalf("chromeSpec(nil) failed: %v", err)
	}
	assertALPN(t, h2, []string{"h2", "http/1.1"})
}

func assertALPN(t *testing.T, spec utls.ClientHelloSpec, want []string) {
	t.Helper()
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			if len(a.AlpnProtocols) != len(want) {
				t.Fatalf("ALPN = %v, want %v", a.AlpnProtocols, want)
			}
			for i := range want {
				if a.AlpnProtocols[i] != want[i] {
					t.Fatalf("ALPN = %v, want %v", a.AlpnProtocols, want)
				}
			}
			return
		}
	}
	t.Fatal("no ALPN extension in the Chrome spec")
}
