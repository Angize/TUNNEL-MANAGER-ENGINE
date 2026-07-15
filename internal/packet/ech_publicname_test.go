package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// buildECHConfigList assembles a wire-format ECHConfigList carrying a single v0xfe0d config with the
// given public_name, mirroring the layout uTLS emits — so echPublicName is tested against the real
// framing, not a hand-waved approximation. When bogusVersion is true the config is tagged with an
// unknown version so the parser must skip it.
func buildECHConfigList(t *testing.T, publicName string, bogusVersion bool) []byte {
	t.Helper()
	var contents cryptobyte.Builder
	contents.AddUint8(1)                                                                             // config_id
	contents.AddUint16(0x20)                                                                         // kem_id (X25519)
	contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })   // public_key
	contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) }) // cipher_suites
	contents.AddUint8(64)                                                                            // maximum_name_length
	contents.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })  // public_name
	contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})                                 // extensions
	body := contents.BytesOrPanic()

	version := echConfigVersion
	if bogusVersion {
		version = 0xabcd
	}
	var list cryptobyte.Builder
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(version)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
	})
	return list.BytesOrPanic()
}

func TestECHPublicName(t *testing.T) {
	// A real config list yields its public name — the SNI the edge presents a cert for on ECH reject.
	if got := echPublicName(buildECHConfigList(t, "cloudflare-ech.com", false)); got != "cloudflare-ech.com" {
		t.Fatalf("echPublicName = %q, want cloudflare-ech.com", got)
	}
	// A list whose only config is an unknown version is skipped -> empty (hook stays unset, safe fallback).
	if got := echPublicName(buildECHConfigList(t, "cloudflare-ech.com", true)); got != "" {
		t.Fatalf("unknown-version config: echPublicName = %q, want empty", got)
	}
	// Garbage / truncated input never panics and yields empty.
	for _, bad := range [][]byte{nil, {}, {0x00}, {0xff, 0xff, 0x00}, []byte("not-an-ech-config")} {
		if got := echPublicName(bad); got != "" {
			t.Fatalf("echPublicName(%v) = %q, want empty", bad, got)
		}
	}
}

// makeLeaf mints a throwaway CA and a leaf cert for dnsName, returning the leaf + a root pool that
// trusts the CA — so verifyOuterCert's chain+hostname logic is tested end-to-end without the system store.
func makeLeaf(t *testing.T, dnsName string) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return leaf, roots
}

func TestVerifyOuterCert(t *testing.T) {
	leaf, roots := makeLeaf(t, "cloudflare-ech.com")

	// A CA-signed cert whose name matches the ECH public name authenticates the reject -> self-heal ok.
	if err := verifyOuterCert([]*x509.Certificate{leaf}, "cloudflare-ech.com", roots); err != nil {
		t.Fatalf("valid public-name cert should verify: %v", err)
	}
	// Same trusted cert but the reject claims a DIFFERENT public name -> rejected (no forged-config harvest).
	if err := verifyOuterCert([]*x509.Certificate{leaf}, "evil.example", roots); err == nil {
		t.Fatal("cert for cloudflare-ech.com must NOT verify against a different public name")
	}
	// A cert that does not chain to a trusted root -> rejected (a MITM's self-signed cert can't self-heal).
	if err := verifyOuterCert([]*x509.Certificate{leaf}, "cloudflare-ech.com", x509.NewCertPool()); err == nil {
		t.Fatal("cert not chaining to a trusted root must NOT verify")
	}
	// No peer certificate at all -> error (this is the reject path with the hook accepting; empty chain).
	if err := verifyOuterCert(nil, "cloudflare-ech.com", roots); err == nil {
		t.Fatal("verifyOuterCert with no peer cert must error")
	}
}
