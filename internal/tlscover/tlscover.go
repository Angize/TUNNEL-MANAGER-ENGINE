// Package tlscover gives a bip TCP connection a REALITY-style TLS cover so it not
// only looks like HTTPS to passive DPI but also survives ACTIVE probing (the
// censor connecting to the server itself and comparing) — the technique Iran's
// filtering uses.
//
// How. The client speaks a Chrome-fingerprinted ClientHello (uTLS) and hides a
// PSK-authenticated token inside the 32-byte legacy session id (normally random,
// so invisible). The server reads the ClientHello before answering:
//
//   - token valid (our client)  -> the server terminates TLS itself (a throwaway
//     cert the client does not verify) and the bip/PSK handshake runs inside.
//   - token absent/invalid (a probe, a real browser, the censor) -> the server
//     transparently PROXIES the whole connection to the REAL destination site
//     (dest:443) and relays bytes. The prober gets that site's genuine
//     certificate and real response, indistinguishable from visiting it.
//
// So dest MUST be a real, reachable, unblocked HTTPS site — it is the cover the
// server borrows. Replays are neutralised by a timestamp window plus a seen-
// ClientHello cache (a replayed hello is treated as a probe → proxied), and a
// replayer cannot complete the inner PSK handshake anyway.
package tlscover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	utls "github.com/refraction-networking/utls"
)

const (
	authMagic  = "TNLREAL1" // 8 bytes; marks a genuine token after decryption
	authWindow = 120        // seconds a token stays valid (replay bound)
	maxRelays  = 256        // concurrent probe→dest relays cap
)

// ErrProbe means the connection was not an authenticated client and has been
// handed off to the dest-proxy relay; the caller must abandon it (do not close).
var ErrProbe = errors.New("tlscover: probe proxied to dest")

var (
	errNotTLS   = errors.New("tlscover: not a TLS handshake")
	errBadHello = errors.New("tlscover: malformed ClientHello")
)

func authKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-bip|v2|reality-auth|" + psk))
	return k[:]
}

// sealToken builds the 32-byte session-id token: AEAD(magic||timestamp) keyed by
// the PSK, using the first 12 bytes of the ClientHello random as the nonce.
func sealToken(psk string, chRandom []byte, ts int64) ([]byte, error) {
	a, err := chacha20poly1305.New(authKey(psk))
	if err != nil {
		return nil, err
	}
	pt := make([]byte, 16)
	copy(pt, authMagic)
	binary.BigEndian.PutUint64(pt[8:], uint64(ts))
	return a.Seal(nil, chRandom[:12], pt, nil), nil // 16 + 16 tag = 32 bytes
}

func openToken(psk string, chRandom, sid []byte) bool {
	if len(sid) != 32 || len(chRandom) < 12 {
		return false
	}
	a, err := chacha20poly1305.New(authKey(psk))
	if err != nil {
		return false
	}
	pt, err := a.Open(nil, chRandom[:12], sid, nil)
	if err != nil || len(pt) != 16 || string(pt[:8]) != authMagic {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(pt[8:16]))
	now := time.Now().Unix()
	return ts >= now-authWindow && ts <= now+authWindow
}

// ClientConn performs the Chrome-mimicking TLS handshake, embedding the auth
// token so the server terminates locally instead of proxying us to dest.
func ClientConn(raw net.Conn, sni, psk string, deadline time.Time) (net.Conn, error) {
	if !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}
	u := utls.UClient(raw, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	tok, err := sealToken(psk, u.HandshakeState.Hello.Random, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	u.HandshakeState.Hello.SessionId = tok
	if err := u.MarshalClientHello(); err != nil {
		return nil, err
	}
	if err := u.Handshake(); err != nil {
		return nil, err
	}
	if !deadline.IsZero() {
		_ = raw.SetDeadline(time.Time{})
	}
	return u, nil
}

// Server is the REALITY-style responder: it authenticates clients by the token
// in their ClientHello and proxies everyone else to the real dest.
type Server struct {
	cert  *tls.Certificate
	psk   string
	dest  string // host:port of the real site to borrow
	relay chan struct{}

	mu   sync.Mutex
	seen map[[32]byte]int64 // ClientHello random -> expiry (anti-replay)
}

// NewServer builds a cover server that borrows destHost (its :443 is proxied to
// for any non-authenticated connection).
func NewServer(psk, destHost string) (*Server, error) {
	cert, err := SelfSignedCert(destHost)
	if err != nil {
		return nil, err
	}
	return &Server{cert: cert, psk: psk, dest: net.JoinHostPort(destHost, "443"),
		relay: make(chan struct{}, maxRelays), seen: map[[32]byte]int64{}}, nil
}

// Handle reads the ClientHello and either returns a TLS conn (authenticated
// client) or proxies the connection to dest and returns ErrProbe.
func (sv *Server) Handle(raw net.Conn, deadline time.Time) (net.Conn, error) {
	if !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}
	hello, random, sid, err := readClientHello(raw)
	if err != nil {
		return nil, err
	}
	if openToken(sv.psk, random, sid) && sv.firstSight(random) {
		if !deadline.IsZero() {
			_ = raw.SetDeadline(time.Time{})
		}
		pc := &prefixConn{Conn: raw, pre: hello}
		// Pin TLS 1.3: our Chrome-fingerprinted client always offers it, and in
		// 1.3 the server Certificate message is encrypted — so the throwaway
		// self-signed cert is never visible to a passive observer (only the real
		// dest's genuine cert, for proxied probes, is ever seen on the wire).
		s := tls.Server(pc, &tls.Config{Certificates: []tls.Certificate{*sv.cert}, MinVersion: tls.VersionTLS13})
		if !deadline.IsZero() {
			_ = s.SetDeadline(deadline)
		}
		if err := s.Handshake(); err != nil {
			return nil, err
		}
		_ = s.SetDeadline(time.Time{})
		return s, nil
	}
	sv.proxyToDest(raw, hello)
	return nil, ErrProbe
}

// firstSight records a ClientHello random and reports whether it is new (an exact
// replay returns false → the caller proxies it to dest, so a replayer sees the
// real site rather than our termination).
func (sv *Server) firstSight(random []byte) bool {
	var k [32]byte
	copy(k[:], random)
	now := time.Now().Unix()
	sv.mu.Lock()
	defer sv.mu.Unlock()
	for kk, exp := range sv.seen {
		if exp < now {
			delete(sv.seen, kk)
		}
	}
	if _, ok := sv.seen[k]; ok {
		return false
	}
	sv.seen[k] = now + authWindow*2
	return true
}

// proxyToDest relays raw<->dest (prepending the buffered ClientHello) in a
// detached goroutine, bounded by the relay cap.
func (sv *Server) proxyToDest(raw net.Conn, hello []byte) {
	select {
	case sv.relay <- struct{}{}:
	default:
		raw.Close() // too many probes in flight; shed
		return
	}
	go func() {
		defer func() { <-sv.relay }()
		dst, err := net.DialTimeout("tcp", sv.dest, 8*time.Second)
		if err != nil {
			raw.Close()
			return
		}
		_ = raw.SetDeadline(time.Time{})
		if _, err := dst.Write(hello); err != nil {
			dst.Close()
			raw.Close()
			return
		}
		done := make(chan struct{}, 2)
		go func() { io.Copy(dst, raw); done <- struct{}{} }()
		go func() { io.Copy(raw, dst); done <- struct{}{} }()
		<-done
		dst.Close()
		raw.Close()
	}()
}

// readClientHello reads exactly one TLS handshake record (the ClientHello),
// returns the raw bytes (for replay) plus the client random and session id.
func readClientHello(c net.Conn) (buf, random, sid []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x16 { // TLS handshake content type
		return nil, nil, nil, errNotTLS
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 40 || recLen > 16384 {
		return nil, nil, nil, errBadHello
	}
	body := make([]byte, recLen)
	if _, err = io.ReadFull(c, body); err != nil {
		return
	}
	buf = append(hdr, body...)
	// body: hs_type(1) hs_len(3) client_version(2) random(32) sid_len(1) sid...
	if len(body) < 39 || body[0] != 0x01 {
		return nil, nil, nil, errBadHello
	}
	random = body[6:38]
	sidLen := int(body[38])
	if 39+sidLen > len(body) {
		return nil, nil, nil, errBadHello
	}
	sid = body[39 : 39+sidLen]
	return buf, random, sid, nil
}

// prefixConn replays pre before delegating reads to the wrapped conn.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// SelfSignedCert makes a throwaway ECDSA certificate for host. Only our own
// client (which does not verify) ever sees it; probes get the real dest's cert.
func SelfSignedCert(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
