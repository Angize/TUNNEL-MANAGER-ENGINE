package dnstun

import (
	"encoding/binary"
	"errors"
	"io"
)

// The reliable session is a byte STREAM (kcp-go), but the tunnel moves discrete L3 packets, so each
// packet is length-prefixed with a 2-byte big-endian length. A tunnel packet never exceeds 65535
// bytes (well under any MTU), so 16 bits is always enough.

var errFrameTooLong = errors.New("dns frame: packet exceeds 65535 bytes")

// WritePacket length-prefixes pkt and writes it to the stream in a single Write so the length and
// body cannot interleave with another packet (the carrier only writes from one goroutine anyway).
func WritePacket(w io.Writer, pkt []byte) error {
	if len(pkt) > 0xFFFF {
		return errFrameTooLong
	}
	out := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(out[:2], uint16(len(pkt)))
	copy(out[2:], pkt)
	_, err := w.Write(out)
	return err
}

// ReadPacket reads one length-prefixed packet from the stream. It returns io.EOF (or another read
// error) when the stream ends, which the carrier treats as the session dying.
func ReadPacket(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
