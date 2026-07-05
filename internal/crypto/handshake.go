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
// Wire (both messages are 48 bytes of uniformly-random-looking data — a 32-byte
// X25519 public value plus a 16-byte PSK-keyed MAC; nothing constant, so it does
// not add a DPI signature):
//
//	msg1 (initiator→responder): e_i(32) || MAC(psk, "bip-hs-i" || e_i)
//	msg2 (responder→initiator): e_r(32) || MAC(psk, "bip-hs-r" || e_i || e_r)
//
// The MAC authenticates the peer as a PSK holder (a prober without the PSK cannot
// forge it, so the responder answers nothing). Session keys then come from
// HKDF(ikm = ECDH || psk, salt = e_i || e_r), so knowing the PSK alone is not
// enough — an attacker also needs an ephemeral private key it never sees.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ephPubLen     = 32
	hsMACLen      = 16
	HandshakeSize = ephPubLen + hsMACLen // 48 bytes on the wire, both messages

	hsTagInit = "bip-hs-i"
	hsTagResp = "bip-hs-r"
)

// Ephemeral is a one-shot X25519 keypair. The private half never leaves the
// process and is meant to be dropped after the session keys are derived.
type Ephemeral struct {
	priv [32]byte
	Pub  [32]byte
}

// GenerateEphemeral makes a fresh X25519 keypair.
func GenerateEphemeral() (*Ephemeral, error) {
	e := &Ephemeral{}
	if _, err := io.ReadFull(rand.Reader, e.priv[:]); err != nil {
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
	k := sha256.Sum256([]byte("tnl-bip|v2|hs-mac|" + psk))
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

// InitMsg builds msg1 for the initiator's ephemeral public key.
func InitMsg(psk string, e *Ephemeral) []byte {
	out := make([]byte, HandshakeSize)
	copy(out, e.Pub[:])
	copy(out[ephPubLen:], hsMAC(psk, hsTagInit, e.Pub[:]))
	return out
}

// ParseInit verifies msg1's MAC and returns the initiator's ephemeral public key.
// A wrong PSK (or a non-handshake packet) fails the MAC and is rejected.
func ParseInit(psk string, msg []byte) (eInit [32]byte, err error) {
	if len(msg) != HandshakeSize {
		return eInit, errors.New("handshake: bad init length")
	}
	copy(eInit[:], msg[:ephPubLen])
	if !hmac.Equal(msg[ephPubLen:], hsMAC(psk, hsTagInit, eInit[:])) {
		return eInit, errors.New("handshake: init MAC mismatch")
	}
	return eInit, nil
}

// RespMsg builds msg2 binding the initiator's key so a response cannot be lifted
// onto a different handshake.
func RespMsg(psk string, eInit [32]byte, e *Ephemeral) []byte {
	out := make([]byte, HandshakeSize)
	copy(out, e.Pub[:])
	copy(out[ephPubLen:], hsMAC(psk, hsTagResp, eInit[:], e.Pub[:]))
	return out
}

// ParseResp verifies msg2 against the initiator key we sent and returns the
// responder's ephemeral public key.
func ParseResp(psk string, eInit [32]byte, msg []byte) (eResp [32]byte, err error) {
	if len(msg) != HandshakeSize {
		return eResp, errors.New("handshake: bad resp length")
	}
	copy(eResp[:], msg[:ephPubLen])
	if !hmac.Equal(msg[ephPubLen:], hsMAC(psk, hsTagResp, eInit[:], eResp[:])) {
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
	kdf := hkdf.New(sha256.New, ikm, salt, []byte("tnl-bip|v2|session|"+name))

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
