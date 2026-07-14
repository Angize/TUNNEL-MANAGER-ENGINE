package packet

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

// These fuzz targets hammer the parsers that consume UNTRUSTED, attacker-controlled bytes straight
// off the wire — a hostile peer or a middlebox can send anything here. The contract under fuzz is
// simply: never panic, never hang, never allocate unboundedly. Each `go test -fuzz` run explores
// millions of inputs looking for a crash. Seeds cover the interesting structural cases.

// FuzzGrpcUnhunk: the gRPC Hunk (protobuf field-1) unwrap on the downstream read path.
func FuzzGrpcUnhunk(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a})
	f.Add([]byte{0x0a, 0x05, 1, 2, 3, 4, 5})
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // oversized varint length
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = grpcUnhunk(data)
	})
}

// FuzzGrpcDeframe: the gRPC length-prefixed message deframer reading from a raw byte stream.
func FuzzGrpcDeframe(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 3, 0x0a, 0x01, 0x41})
	f.Add([]byte{0, 0xff, 0xff, 0xff, 0xff}) // huge length prefix (must be rejected, not OOM)
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &grpcDeframingReader{r: bytes.NewReader(data)}
		buf := make([]byte, 512)
		for i := 0; i < 10000; i++ { // bounded so a pathological stream can't loop forever in the harness
			if _, err := r.Read(buf); err != nil {
				return
			}
		}
	})
}

// FuzzReadWSFrame: the WebSocket frame header/length/mask parser (client reads server frames here).
func FuzzReadWSFrame(f *testing.F) {
	f.Add([]byte{0x82, 0x03, 1, 2, 3})                                     // unmasked, len 3
	f.Add([]byte{0x82, 0x83, 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3})            // masked, len 3
	f.Add([]byte{0x82, 0x7e, 0xff, 0xff})                                 // 16-bit extended length
	f.Add([]byte{0x82, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // 64-bit extended length
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readWSFrame(bufio.NewReader(bytes.NewReader(data)))
	})
}

// FuzzParseSTUN: the STUN-cover header parser on the flux carrier's inbound path.
func FuzzParseSTUN(f *testing.F) {
	f.Add(make([]byte, 24))
	seed := make([]byte, 40)
	seed[4], seed[5], seed[6], seed[7] = 0x21, 0x12, 0xa4, 0x42 // stunMagic
	seed[22], seed[23] = 0x00, 0x10
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseSTUN(data)
	})
}

// FuzzFecInput: the FEC decoder's per-packet input path (header parse + RS reconstruction). An
// unauthenticated peer can spray these, so bounds and the anti-amplification byte budget must hold.
func FuzzFecInput(f *testing.F) {
	f.Add([]byte{0x01, 0xff})                                     // passthrough
	f.Add([]byte{0x02, 0, 0, 0, 1, 0, 4, 2, 4, 0, 2, 0xaa, 0xbb}) // a data shard header + shard
	f.Fuzz(func(t *testing.T, data []byte) {
		d := newFecDecoder(func([]byte) {})
		d.input(data)
	})
}

// FuzzReadFrameClear: the core wire-frame decoder in clear mode (no crypto, no obfs) — length
// prefix + magic + type + payload slice. Every inbound packet flows through readFrame, so a panic
// here on hostile bytes is a remote-crash DoS.
func FuzzReadFrameClear(f *testing.F) {
	f.Add([]byte{0x00, 0x03, magic, typeData, 0x41})
	f.Add([]byte{0x00, 0x02, magic, typePing})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		cf := &connFramer{r: bufio.NewReader(bytes.NewReader(data))}
		_, _, _, _, _ = cf.readFrame()
	})
}

// FuzzReadFrameCrypto: the same decoder with crypto ON — every frame is AEAD-sealed, so hostile
// bytes must fail Open cleanly (never panic) and never be accepted. Uses a real sealer keyed by a
// fixed PSK; the fuzzer explores the sealed-blob parsing and the Open failure paths.
func FuzzReadFrameCrypto(f *testing.F) {
	s, err := crypto.NewSealer(crypto.CipherChaCha, "fuzz-psk-0123456789abcdef", false)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0x00, 0x14, magic, typeData, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	f.Add([]byte{0x00, 0x02, magic, typeData})
	f.Fuzz(func(t *testing.T, data []byte) {
		cf := &connFramer{r: bufio.NewReader(bytes.NewReader(data)), sealer: s}
		_, _, _, _, _ = cf.readFrame()
	})
}

// FuzzObfsOpen: the obfs open primitive (AEAD open of a length-unmasked frame body). Hostile bytes
// must fail cleanly. Sealer keyed by a fixed PSK.
func FuzzObfsOpen(f *testing.F) {
	s, err := crypto.NewSealer(crypto.CipherChaCha, "fuzz-psk-0123456789abcdef", false)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, _ = obfsOpen(s, data)
	})
}
