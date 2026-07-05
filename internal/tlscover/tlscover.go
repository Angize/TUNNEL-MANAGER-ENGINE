// Package tlscover wraps a bip TCP connection in a real TLS session so the wire
// looks like ordinary HTTPS instead of "fully-encrypted" random bytes — the
// traffic class that entropy/first-packet classifiers (GFW, Iran DPI) block.
//
// The client speaks a Chrome-fingerprinted ClientHello via uTLS, so the opening
// flight matches a real browser (JA3), not Go's TLS stack. The server answers a
// normal TLS handshake with a self-signed certificate. The certificate is NOT
// trusted or verified — authentication is done by the PSK/ephemeral handshake
// that runs INSIDE this TLS tunnel — so InsecureSkipVerify is intentional; TLS
// here is camouflage, not the security boundary.
package tlscover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ClientConn performs a Chrome-mimicking TLS handshake over raw and returns the
// wrapped connection. sni is the server name presented (a plausible host); the
// server certificate is not verified.
func ClientConn(raw net.Conn, sni string, deadline time.Time) (net.Conn, error) {
	if !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}
	cfg := &utls.Config{ServerName: sni, InsecureSkipVerify: true}
	u := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	if err := u.Handshake(); err != nil {
		return nil, err
	}
	if !deadline.IsZero() {
		_ = raw.SetDeadline(time.Time{}) // clear; the carrier sets its own deadlines
	}
	return u, nil
}

// ServerConn completes the server side of the TLS handshake with cert.
func ServerConn(raw net.Conn, cert *tls.Certificate, deadline time.Time) (net.Conn, error) {
	if !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	s := tls.Server(raw, cfg)
	if err := s.Handshake(); err != nil {
		return nil, err
	}
	if !deadline.IsZero() {
		_ = raw.SetDeadline(time.Time{})
	}
	return s, nil
}

// SelfSignedCert makes a throwaway ECDSA certificate for the given host. It only
// needs to complete a TLS handshake (never validated by the peer).
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
