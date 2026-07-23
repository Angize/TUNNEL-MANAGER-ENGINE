package dnstun

import (
	"encoding/base32"
	"errors"
	"strings"
)

// lowB32 is lowercase, unpadded base32 (RFC 4648 alphabet, lowercased). Every symbol is a valid
// DNS label character, and because we lowercase on BOTH encode and decode, a recursive resolver's
// 0x20 case randomization (which flips the case of query-name letters as an anti-spoofing measure)
// is neutralized: the server lowercases the received name before decoding it back to bytes.
var lowB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

const (
	maxLabel = 63  // DNS label length limit
	maxName  = 255 // DNS name wire-length limit
	maxTXT   = 255 // one TXT character-string
	// nonceLen is the length (in base32 chars) of the per-query random label prepended to EVERY
	// query name. It makes every name unique — including the idle poll and the handshake init
	// retransmit, which are otherwise byte-identical every time — so a recursive resolver can never
	// answer them from its cache or coalesce them: each query reaches our authoritative server and
	// the downstream datagram it carries actually returns. Without this, a resolver honoring TTL=0
	// is the only thing that keeps the tunnel alive, and Google/most resolvers coalesce or briefly
	// cache identical in-flight names, which starves the handshake and the session never converges.
	nonceLen = 8
)

// nonceWire is the wire cost of the nonce label: its length octet plus its bytes.
const nonceWire = 1 + nonceLen

var (
	errTooBig   = errors.New("dns codec: datagram exceeds one-message capacity")
	errBadName  = errors.New("dns codec: query name not under the zone")
	errBadNonce = errors.New("dns codec: nonce label empty or too long")
)

// Codec maps datagrams onto DNS messages under a fixed delegated zone. UPSTREAM (client→server)
// rides the query NAME as base32 labels; DOWNSTREAM (server→client) rides a single TXT record's
// RDATA. A single TXT (ordered bytes) is used rather than several A/AAAA records because a resolver
// may reorder answer records — which would corrupt data split across them; per-record sequencing
// for a lower-signature A/AAAA form is deferred to hardening. The codec is pure and transport-free.
type Codec struct {
	zone  string // fully-qualified, lowercase, with a single trailing dot (e.g. "t.example.com.")
	maxUp int    // max raw datagram bytes that fit in one query name's data labels
}

// NewCodec builds a codec for a delegated zone. It errors if the zone is empty/malformed or so long
// that no room is left for upstream data.
func NewCodec(zone string) (*Codec, error) {
	z := strings.ToLower(strings.TrimSpace(zone))
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return nil, errors.New("dns codec: empty zone")
	}
	for _, lbl := range strings.Split(z, ".") {
		if lbl == "" || len(lbl) > maxLabel {
			return nil, errors.New("dns codec: malformed zone label (empty or too long)")
		}
	}
	c := &Codec{zone: z + "."}
	c.maxUp = c.computeMaxUpstream()
	if c.maxUp < 16 {
		return nil, errors.New("dns codec: zone too long, no room for tunnel data")
	}
	return c, nil
}

// MaxUpstream is the largest datagram (raw bytes) that fits in one query — the caller sizes the KCP
// MTU (plus AEAD/kind overhead) so every KCP datagram rides exactly one DNS query.
func (c *Codec) MaxUpstream() int { return c.maxUp }

// Zone returns the fully-qualified delegated zone (trailing dot).
func (c *Codec) Zone() string { return c.zone }

// zoneWireLen is the wire length of the zone name (label length-octets + bytes + the root octet).
func zoneWireLen(zone string) int {
	n := 1 // root label (0x00)
	for _, lbl := range strings.Split(strings.TrimSuffix(zone, "."), ".") {
		if lbl != "" {
			n += 1 + len(lbl)
		}
	}
	return n
}

// computeMaxUpstream finds the max raw byte count whose base32 form, split into <=63-char labels,
// fits alongside the zone AND the per-query nonce label inside the 255-byte name limit.
func (c *Codec) computeMaxUpstream() int {
	dataWire := maxName - zoneWireLen(c.zone) - nonceWire
	if dataWire <= 0 {
		return 0
	}
	// Largest label-char count chars with chars + ceil(chars/63) (the per-label length octets) <= dataWire.
	chars := 0
	for {
		next := chars + 1
		if next+(next+maxLabel-1)/maxLabel > dataWire {
			break
		}
		chars = next
	}
	return chars * 5 / 8 // base32: 8 chars per 5 bytes; floor gives the max raw bytes fitting in `chars`
}

// EncodeName builds the query name carrying data: a per-query nonce label (leftmost, makes the name
// unique so a resolver can't cache/coalesce it) followed by base32(data) split into <=63-char labels
// under the zone. It errors if data exceeds MaxUpstream or the nonce is empty/over-long. The nonce is
// supplied by the caller (the transport) so the codec stays pure; a poll is EncodeName(nil, nonce),
// which yields "<nonce>.<zone>" — unique, yet carrying no upstream payload.
func (c *Codec) EncodeName(data []byte, nonce string) (string, error) {
	if len(data) > c.maxUp {
		return "", errTooBig
	}
	if nonce == "" || len(nonce) > maxLabel {
		return "", errBadNonce
	}
	var b strings.Builder
	b.WriteString(nonce)
	b.WriteByte('.')
	s := lowB32.EncodeToString(data)
	for len(s) > 0 {
		n := len(s)
		if n > maxLabel {
			n = maxLabel
		}
		b.WriteString(s[:n])
		b.WriteByte('.')
		s = s[n:]
	}
	b.WriteString(c.zone)
	return b.String(), nil
}

// DecodeName extracts the datagram from a query name under the zone, tolerating a missing/extra
// trailing dot and any 0x20 case randomization the resolver applied. The leftmost label is the
// per-query nonce (see EncodeName) and is discarded; the remaining labels are the base32 data. A
// nonce-only name ("<nonce>.<zone>") or the bare zone carries zero upstream bytes (a poll).
func (c *Codec) DecodeName(name string) ([]byte, error) {
	nl := normName(name) // lower-case, trimmed, single trailing dot — same normalization as the zone form
	// Require a real label boundary before the zone: "<labels>.<zone>" or a bare "<zone>" query.
	// A plain HasSuffix would accept e.g. "abt.example.com" for zone "t.example.com" and mis-parse
	// the foreign label "ab" as a nonce.
	if nl != c.zone && !strings.HasSuffix(nl, "."+c.zone) {
		return nil, errBadName
	}
	prefix := strings.TrimSuffix(nl[:len(nl)-len(c.zone)], ".") // nonce + data labels, no trailing dot
	if prefix == "" {
		return []byte{}, nil // bare zone (external probe), no nonce/data
	}
	labels := strings.Split(prefix, ".")
	data := labels[1:] // drop the leftmost nonce label
	if len(data) == 0 {
		return []byte{}, nil // nonce-only name: a poll with no upstream payload
	}
	return lowB32.DecodeString(strings.Join(data, ""))
}

// EncodeTXT packs a downstream datagram into TXT character-strings (<=255 bytes each). A datagram
// never exceeds MaxUpstream (< 255), so this is normally a single string; it splits defensively.
func (c *Codec) EncodeTXT(data []byte) []string {
	if len(data) == 0 {
		return []string{""}
	}
	var out []string
	for len(data) > 0 {
		n := len(data)
		if n > maxTXT {
			n = maxTXT
		}
		out = append(out, string(data[:n]))
		data = data[n:]
	}
	return out
}

// DecodeTXT reassembles a downstream datagram from a TXT record's character-strings (in order).
func (c *Codec) DecodeTXT(txt []string) []byte {
	var out []byte
	for _, s := range txt {
		out = append(out, s...)
	}
	return out
}
