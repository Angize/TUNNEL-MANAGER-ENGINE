package packet

import (
	"bytes"
	"net"
	"testing"
)

// captureConn is a net.Conn that records each Write as a separate segment so a test can assert how
// the first write was fragmented.
type captureConn struct {
	net.Conn
	writes [][]byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	c.writes = append(c.writes, b)
	return len(p), nil
}

// The embedded net.Conn is nil, so override the addr accessors the fake/disorder paths probe.
func (c *captureConn) LocalAddr() net.Addr  { return nil }
func (c *captureConn) RemoteAddr() net.Addr { return nil }

func TestFragConnAutoSplitsInsideHostname(t *testing.T) {
	cap := &captureConn{}
	f := newFragConn(cap, "cdn.spacefly.ir", 0, "split", 0) // auto: split in the middle of the hostname
	// a ClientHello-shaped buffer with the cleartext SNI embedded
	hello := append([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00}, []byte("....cdn.spacefly.ir....rest....")...)
	if _, err := f.Write(hello); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.writes) != 2 {
		t.Fatalf("first write should split into 2 segments, got %d", len(cap.writes))
	}
	// Neither segment may contain the full hostname; concatenation must equal the original.
	for i, w := range cap.writes {
		if bytes.Contains(w, []byte("cdn.spacefly.ir")) {
			t.Fatalf("segment %d still contains the full hostname", i)
		}
	}
	if got := append(append([]byte{}, cap.writes[0]...), cap.writes[1]...); !bytes.Equal(got, hello) {
		t.Fatalf("reassembled bytes differ from the original ClientHello")
	}
	// Subsequent writes pass through unsplit.
	if _, err := f.Write([]byte("data")); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if len(cap.writes) != 3 || string(cap.writes[2]) != "data" {
		t.Fatalf("post-handshake writes must pass through whole, got %v", cap.writes)
	}
}

func TestFragConnExplicitPos(t *testing.T) {
	cap := &captureConn{}
	f := newFragConn(cap, "example.com", 4, "split", 0) // explicit offset overrides auto
	if _, err := f.Write([]byte("ABCDEFGH")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.writes) != 2 || string(cap.writes[0]) != "ABCD" || string(cap.writes[1]) != "EFGH" {
		t.Fatalf("explicit split at 4 wrong: %q", cap.writes)
	}
}

func TestFragConnNoSplitWhenHostAbsent(t *testing.T) {
	cap := &captureConn{}
	f := newFragConn(cap, "hidden.example", 0, "split", 0) // ECH-like: hostname not in cleartext
	if _, err := f.Write([]byte("no matching host here")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.writes) != 1 {
		t.Fatalf("absent hostname must write whole (no split), got %d segments", len(cap.writes))
	}
}

func TestFragConnOutOfRangePos(t *testing.T) {
	cap := &captureConn{}
	f := newFragConn(cap, "", 999, "split", 0) // pos past the buffer -> write whole
	if _, err := f.Write([]byte("short")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.writes) != 1 || string(cap.writes[0]) != "short" {
		t.Fatalf("out-of-range pos must write whole, got %q", cap.writes)
	}
}

func TestFragConnDisorderFallsBackToSplit(t *testing.T) {
	cap := &captureConn{} // no SyscallConn -> disorder can't set a per-segment TTL, must still split
	f := newFragConn(cap, "cdn.spacefly.ir", 0, "disorder", 4)
	hello := append([]byte{0x16, 0x03, 0x01}, []byte("xxcdn.spacefly.iryy")...)
	if _, err := f.Write(hello); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.writes) != 2 {
		t.Fatalf("disorder without a raw fd must fall back to a 2-segment split, got %d", len(cap.writes))
	}
	if got := append(append([]byte{}, cap.writes[0]...), cap.writes[1]...); !bytes.Equal(got, hello) {
		t.Fatalf("reassembled bytes differ from the original ClientHello")
	}
}

func TestFragConnFakeFallsBackToSplit(t *testing.T) {
	cap := &captureConn{} // no *net.TCPAddr / no raw fd -> fake can't inject, must still split
	f := newFragConn(cap, "cdn.spacefly.ir", 0, "fake", 4)
	hello := append([]byte{0x16, 0x03, 0x01}, []byte("xxcdn.spacefly.iryy")...)
	if _, err := f.Write(hello); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(cap.writes) != 2 {
		t.Fatalf("fake without a real 4-tuple/fd must fall back to a 2-segment split, got %d", len(cap.writes))
	}
	if got := append(append([]byte{}, cap.writes[0]...), cap.writes[1]...); !bytes.Equal(got, hello) {
		t.Fatalf("reassembled bytes differ from the original ClientHello")
	}
}

func TestBadTCPChecksum(t *testing.T) {
	seg := make([]byte, 20)
	seg[16], seg[17] = 0x12, 0x34
	badTCPChecksum(seg)
	if seg[16] == 0x12 && seg[17] == 0x34 {
		t.Fatal("badTCPChecksum must change the TCP checksum field so the server drops the fake")
	}
	badTCPChecksum([]byte{1, 2, 3}) // too short -> safe no-op, must not panic
}

func TestDecoySNISameLength(t *testing.T) {
	for _, n := range []int{0, 1, 5, 19, 40} {
		if got := len(decoySNI(n)); got != n {
			t.Fatalf("decoySNI(%d) len = %d, want %d (must preserve the SNI length field)", n, got, n)
		}
	}
	if bytes.Contains(decoySNI(19), []byte("cdn.spacefly.ir")) {
		t.Fatal("decoy must not contain the real (blocked) hostname")
	}
}
