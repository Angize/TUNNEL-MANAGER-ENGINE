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
// Wire. Each message is a clear per-message random nonce followed by the
// masked 48-byte authenticated body:
//
//	msg1 (initiator→responder): nonce(12) || MASK( e_i(32) || MAC(psk,"core-hs-i"||e_i) )
//	msg2 (responder→initiator): nonce(12) || MASK( e_r(32) || MAC(psk,"core-hs-r"||e_i||e_r) )
//
// MASK = ChaCha20(key=HKDF-ish(psk), nonce) XOR body. A raw X25519 public value is
// a canonical curve point whose top wire bit is always 0, so without masking a
// passive classifier could aggregate that bias across the many handshakes a single
// IP receives into a per-IP fingerprint (the class of signal that has gotten
// Shadowsocks/obfs servers blocked). XORing the body under a per-message keystream
// makes the whole message uniformly random on the wire; the nonce is public but
// the mask key is PSK-derived, so a prober without the PSK sees only noise and,
// failing the MAC after unmasking, is answered with nothing.
//
// The MAC authenticates the peer as a PSK holder. Session keys then come from
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
	ephPubLen  = 32
	hsMACLen   = 16
	hsBodyLen  = ephPubLen + hsMACLen // 48: the PSK-authenticated body (public value || MAC)
	hsNonceLen = 12                   // per-message random ChaCha20 nonce, carried in the clear ahead of the body

	// HandshakeSize is the on-wire length of both handshake messages: the clear nonce plus the masked
	// body. Every carrier reads exactly this many bytes / expects a datagram of this size.
	HandshakeSize = hsNonceLen + hsBodyLen // 60 bytes

	hsTagInit = "core-hs-i"
	hsTagResp = "core-hs-r"
)

// Ephemeral is a one-shot X25519 keypair plus the random nonce that masks its handshake message. The
// private half never leaves the process and is meant to be dropped after the session keys are derived.
type Ephemeral struct {
	priv  [32]byte
	Pub   [32]byte
	nonce [hsNonceLen]byte
}

// GenerateEphemeral makes a fresh X25519 keypair and the per-message mask nonce.
func GenerateEphemeral() (*Ephemeral, error) {
	e := &Ephemeral{}
	if _, err := io.ReadFull(rand.Reader, e.priv[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, e.nonce[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(e.priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(e.Pub[:], pub)
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

// hsMask XORs buf in place with the PSK-keyed ChaCha20 keystream over nonce (XOR is its own inverse, so
// the same call both masks and unmasks). The 32-byte key and the 12-byte nonce are always valid ChaCha20
// inputs, so the constructor cannot fail here; a non-nil error would be a programming bug, not a runtime
// condition.
func hsMask(psk string, nonce, buf []byte) {
	c, err := chacha20.NewUnauthenticatedCipher(hsMaskKey(psk), nonce)
	if err != nil {
		panic("crypto: handshake mask cipher: " + err.Error())
	}
	c.XORKeyStream(buf, buf)
}

// InitMsg builds msg1 for the initiator's ephemeral public key.
func InitMsg(psk string, e *Ephemeral) []byte {
	out := make([]byte, HandshakeSize)
	copy(out, e.nonce[:])
	body := out[hsNonceLen:]
	copy(body, e.Pub[:])
	copy(body[ephPubLen:], hsMAC(psk, hsTagInit, e.Pub[:]))
	hsMask(psk, e.nonce[:], body)
	return out
}

// ParseInit unmasks msg1, verifies its MAC and returns the initiator's ephemeral public key. A wrong
// PSK (or a non-handshake packet) unmasks to bytes whose MAC does not verify and is rejected.
func ParseInit(psk string, msg []byte) (eInit [32]byte, err error) {
	if len(msg) != HandshakeSize {
		return eInit, errors.New("handshake: bad init length")
	}
	body := make([]byte, hsBodyLen)
	copy(body, msg[hsNonceLen:])
	hsMask(psk, msg[:hsNonceLen], body)
	copy(eInit[:], body[:ephPubLen])
	if !hmac.Equal(body[ephPubLen:], hsMAC(psk, hsTagInit, eInit[:])) {
		return eInit, errors.New("handshake: init MAC mismatch")
	}
	return eInit, nil
}

// RespMsg builds msg2 binding the initiator's key so a response cannot be lifted
// onto a different handshake.
func RespMsg(psk string, eInit [32]byte, e *Ephemeral) []byte {
	out := make([]byte, HandshakeSize)
	copy(out, e.nonce[:])
	body := out[hsNonceLen:]
	copy(body, e.Pub[:])
	copy(body[ephPubLen:], hsMAC(psk, hsTagResp, eInit[:], e.Pub[:]))
	hsMask(psk, e.nonce[:], body)
	return out
}

// ParseResp unmasks msg2, verifies it against the initiator key we sent and returns the responder's
// ephemeral public key.
func ParseResp(psk string, eInit [32]byte, msg []byte) (eResp [32]byte, err error) {
	if len(msg) != HandshakeSize {
		return eResp, errors.New("handshake: bad resp length")
	}
	body := make([]byte, hsBodyLen)
	copy(body, msg[hsNonceLen:])
	hsMask(psk, msg[:hsNonceLen], body)
	copy(eResp[:], body[:ephPubLen])
	if !hmac.Equal(body[ephPubLen:], hsMAC(psk, hsTagResp, eInit[:], eResp[:])) {
		return eResp, errors.New("handshake: resp MAC mismatch")
	}
	return eResp, nil
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
