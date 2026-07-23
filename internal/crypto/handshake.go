// Handshake: an ephemeral X25519 key agreement, authenticated by the PSK, that
// establishes per-session AEAD keys with FORWARD SECRECY and FRESHNESS.
//
// Why. The static-PSK sealer (NewSealer) derives the same keys every run, so a
// frame captured from an earlier session still AEAD-opens after the peer
// restarts — the root of the cross-session replay / peer-hijack finding — and a
// one-time PSK disclosure decrypts all past traffic (no forward secrecy). Binding
// each session to a fresh ephemeral ECDH fixes both:
//
//   - Forward secrecy: session keys come from ephemeral private keys that are
//     discarded after the handshake; capturing the PSK later cannot reconstruct
//     them. (#12)
//   - Anti-replay / anti-rebind: the responder contributes a fresh ephemeral, so
//     every session's keys differ. A replayed old-session data frame fails to
//     open under the current keys and is dropped — it can no longer rebind the
//     peer or inject a packet. (#1)
//
// Wire. Each message is a clear per-message random nonce, then the MASKED
// (padLen || public value || MAC || pad), where pad is padLen bytes:
//
//	msg: nonce(12) || MASK( padLen(1) || e(32) || MAC(psk,tag||…) || pad(padLen) )
//
// MASK = ChaCha20(key=derived(psk), nonce) XOR the rest. Two anti-fingerprint
// properties:
//
//   - Uniform bytes: a raw X25519 public value is a canonical curve point whose
//     top wire bit is always 0, a bias a passive classifier could aggregate per-IP
//     (the class of signal that has gotten Shadowsocks/obfs servers blocked).
//     Masking under a per-message keystream makes the whole message uniformly
//     random on the wire; the pad region is keystream over zeros, so it too looks
//     random with no separate CSPRNG draw.
//   - Variable size: padLen is uniform in [0,255], so the message length (and thus
//     the opening byte-count sequence) is no longer a fixed 48→48 signature. A
//     stream reader takes the fixed HandshakeCoreSize prefix, unmasks padLen and
//     consumes the trailing pad (ReadHandshake); a datagram carries core||pad whole.
//
// The mask key is PSK-derived, so a prober without the PSK sees only noise and,
// failing the MAC after unmasking, is answered with nothing. Session keys come from
// HKDF(ikm = ECDH || psk, salt = e_i || e_r), so knowing the PSK alone is not
// enough — an attacker also needs an ephemeral private key it never sees.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ephPubLen   = 32
	hsMACLen    = 16
	hsBodyLen   = ephPubLen + hsMACLen // 48: public value || MAC (the authenticated body)
	hsNonceLen  = 12                   // clear per-message ChaCha20 nonce
	hsPadLenLen = 1                    // one masked byte carrying the trailing-pad length

	// HandshakeCoreSize is the FIXED prefix every message starts with: the clear nonce plus the masked
	// (padLen || body). A variable-length random pad follows, so the on-wire message size varies and the
	// opening no longer carries a fixed byte-count signature. A stream reader consumes this core, learns
	// padLen and discards the pad (ReadHandshake); a datagram carries core||pad in one packet.
	HandshakeCoreSize = hsNonceLen + hsPadLenLen + hsBodyLen // 61

	hsTagInit = "core-hs-i"
	hsTagResp = "core-hs-r"
)

// Ephemeral is a one-shot X25519 keypair plus the per-message mask nonce and pad length. The private
// half never leaves the process and is meant to be dropped after the session keys are derived.
type Ephemeral struct {
	priv   [32]byte
	Pub    [32]byte
	nonce  [hsNonceLen]byte
	padLen byte
}

// GenerateEphemeral makes a fresh X25519 keypair, the per-message mask nonce, and a random pad length.
func GenerateEphemeral() (*Ephemeral, error) {
	e := &Ephemeral{}
	if _, err := io.ReadFull(rand.Reader, e.priv[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, e.nonce[:]); err != nil {
		return nil, err
	}
	var pb [1]byte
	if _, err := io.ReadFull(rand.Reader, pb[:]); err != nil {
		return nil, err
	}
	e.padLen = pb[0] // one uniform byte in [0,255]; a padded handshake stays well under the MTU
	pub, err := curve25519.X25519(e.priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(e.Pub[:], pub)
	return e, nil
}

// GenerateEphemeralNoPad is GenerateEphemeral with the handshake pad disabled, for a carrier (the DNS
// tunnel) that re-encodes the handshake into its own wire (DNS query names) under a small per-query
// budget. On-wire size padding neither helps there (the raw handshake bytes never appear on the wire)
// nor fits that budget, so such a carrier keeps the message at the minimum HandshakeCoreSize.
func GenerateEphemeralNoPad() (*Ephemeral, error) {
	e, err := GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	e.padLen = 0
	return e, nil
}

func hsMACKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|hs-mac|" + psk))
	return k[:]
}

func hsMAC(psk, tag string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, hsMACKey(psk))
	m.Write([]byte(tag))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:hsMACLen]
}

func hsMaskKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|hs-mask|" + psk))
	return k[:]
}

// hsMask XORs buf in place with the PSK-keyed ChaCha20 keystream over nonce, starting from keystream
// offset 0 (XOR is its own inverse, so the same call masks and unmasks). The 32-byte key and 12-byte
// nonce are always valid ChaCha20 inputs, so the constructor cannot fail here — a non-nil error would
// be a programming bug, not a runtime condition.
func hsMask(psk string, nonce, buf []byte) {
	c, err := chacha20.NewUnauthenticatedCipher(hsMaskKey(psk), nonce)
	if err != nil {
		panic("crypto: handshake mask cipher: " + err.Error())
	}
	c.XORKeyStream(buf, buf)
}

// buildMsg assembles nonce || MASK( padLen || body || pad ) for e, where body is the 48-byte
// (public value || mac). The pad region is left zero and turned into keystream by the mask.
func buildMsg(psk string, e *Ephemeral, mac []byte) []byte {
	out := make([]byte, HandshakeCoreSize+int(e.padLen))
	copy(out, e.nonce[:])
	m := out[hsNonceLen:] // padLen(1) || pubkey(32) || mac(16) || pad(padLen)
	m[0] = e.padLen
	copy(m[hsPadLenLen:], e.Pub[:])
	copy(m[hsPadLenLen+ephPubLen:], mac)
	hsMask(psk, e.nonce[:], m)
	return out
}

// InitMsg builds msg1 for the initiator's ephemeral public key.
func InitMsg(psk string, e *Ephemeral) []byte {
	return buildMsg(psk, e, hsMAC(psk, hsTagInit, e.Pub[:]))
}

// RespMsg builds msg2 binding the initiator's key so a response cannot be lifted onto a different
// handshake.
func RespMsg(psk string, eInit [32]byte, e *Ephemeral) []byte {
	return buildMsg(psk, e, hsMAC(psk, hsTagResp, eInit[:], e.Pub[:]))
}

// parseBody unmasks the fixed (padLen || pubkey || MAC) core out of a message and returns the peer
// public key and its MAC. The trailing pad is ignored (a stream reader consumed it separately; a
// datagram simply carries it), so msg need only be at least HandshakeCoreSize bytes.
func parseBody(psk string, msg []byte) (pub [32]byte, mac []byte, err error) {
	if len(msg) < HandshakeCoreSize {
		return pub, nil, errors.New("handshake: short message")
	}
	body := make([]byte, hsPadLenLen+hsBodyLen)
	copy(body, msg[hsNonceLen:HandshakeCoreSize])
	hsMask(psk, msg[:hsNonceLen], body) // body[0]=padLen (unused here), then pubkey||MAC
	copy(pub[:], body[hsPadLenLen:hsPadLenLen+ephPubLen])
	return pub, body[hsPadLenLen+ephPubLen : hsPadLenLen+hsBodyLen], nil
}

// ParseInit unmasks msg1, verifies its MAC and returns the initiator's ephemeral public key. A wrong
// PSK (or a non-handshake packet) unmasks to bytes whose MAC does not verify and is rejected.
func ParseInit(psk string, msg []byte) (eInit [32]byte, err error) {
	pub, mac, err := parseBody(psk, msg)
	if err != nil {
		return eInit, err
	}
	if !hmac.Equal(mac, hsMAC(psk, hsTagInit, pub[:])) {
		return eInit, errors.New("handshake: init MAC mismatch")
	}
	return pub, nil
}

// ParseResp unmasks msg2, verifies it against the initiator key we sent and returns the responder's
// ephemeral public key.
func ParseResp(psk string, eInit [32]byte, msg []byte) (eResp [32]byte, err error) {
	pub, mac, err := parseBody(psk, msg)
	if err != nil {
		return eResp, err
	}
	if !hmac.Equal(mac, hsMAC(psk, hsTagResp, eInit[:], pub[:])) {
		return eResp, errors.New("handshake: resp MAC mismatch")
	}
	return pub, nil
}

// ReadHandshake reads one (possibly padded) handshake message from a STREAM: the fixed core, then the
// trailing random pad whose length is carried (masked) in the core. It returns the core bytes for
// ParseInit/ParseResp. Datagram carriers do not use this — a datagram delivers core||pad whole and is
// passed straight to ParseInit/ParseResp.
func ReadHandshake(r io.Reader, psk string) ([]byte, error) {
	core := make([]byte, HandshakeCoreSize)
	if _, err := io.ReadFull(r, core); err != nil {
		return nil, err
	}
	// Unmask just the padLen byte (keystream offset 0) to learn how much pad trails the core.
	lead := []byte{core[hsNonceLen]}
	hsMask(psk, core[:hsNonceLen], lead)
	if pad := int(lead[0]); pad > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(pad)); err != nil {
			return nil, err
		}
	}
	return core, nil
}

// SessionSealer derives the per-session Sealer from a completed handshake. ownPriv
// is this side's ephemeral private key, peerPub the other side's public key, and
// eInit/eResp the two public keys in fixed (initiator, responder) order so both
// ends salt the KDF identically. isClient marks which end we are (the initiator
// is always the client).
func SessionSealer(cipherName, psk string, own *Ephemeral, peerPub, eInit, eResp [32]byte, isClient bool) (*Sealer, error) {
	name := ResolveCipher(cipherName)
	_, keyLen, err := aeadFactory(name)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(own.priv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	// ikm = ECDH || PSK: an attacker needs BOTH an ephemeral private key (forward
	// secrecy) AND the PSK (authentication). salt = e_i || e_r (fresh per session).
	ikm := append(append([]byte{}, shared...), []byte(psk)...)
	salt := append(append([]byte{}, eInit[:]...), eResp[:]...)
	kdf := hkdf.New(sha256.New, ikm, salt, []byte("tnl-core|v2|session|"+name))

	c2sKey := make([]byte, keyLen)
	s2cKey := make([]byte, keyLen)
	c2sMask := make([]byte, maskKeyLen)
	s2cMask := make([]byte, maskKeyLen)
	for _, b := range [][]byte{c2sKey, s2cKey, c2sMask, s2cMask} {
		if _, err := io.ReadFull(kdf, b); err != nil {
			return nil, err
		}
	}
	return sealerFromKeys(name, c2sKey, s2cKey, c2sMask, s2cMask, isClient)
}
