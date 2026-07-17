package dnstun

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestDNSMessageHelpersRoundTrip(t *testing.T) {
	// A query built by the client must parse back to the same id+name on the server, and a TXT
	// response must parse back to the same bytes on the client.
	name := "abcd.ef23.t.example.com."
	q, err := buildQuery(0x1234, name)
	if err != nil {
		t.Fatal(err)
	}
	id, gotName, ok := parseQuery(q)
	if !ok || id != 0x1234 || gotName != name {
		t.Fatalf("parseQuery = %d,%q,%v want 0x1234,%q,true", id, gotName, ok, name)
	}
	payload := []byte{0x00, 0x01, 0xff, 0xfe, 'x', 'y'}
	resp, err := buildResponseTXT(0x1234, name, []string{string(payload)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseResponseTXT(resp, 0x1234)
	if err != nil {
		t.Fatalf("parseResponseTXT: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("TXT payload round-trip: got %x want %x", got, payload)
	}
	if _, err := parseResponseTXT(resp, 0x9999); err == nil {
		t.Fatal("parseResponseTXT accepted a mismatched id")
	}
}

// TestDNSCarrierEndToEnd is the Phase-B proof: a real client transport (DNS queries over UDP) and a
// real server transport (authoritative responder) carry the full session layer — handshake + AEAD
// + KCP — and tunnel a byte stream in both directions over actual DNS message exchanges.
func TestDNSCarrierEndToEnd(t *testing.T) {
	// Snappy polling for the test; restore afterwards.
	origPoll, origTO := pollInterval, queryTimeout
	pollInterval, queryTimeout = 3*time.Millisecond, 2*time.Second
	defer func() { pollInterval, queryTimeout = origPoll, origTO }()

	codec, err := NewCodec("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	mtu := codec.MaxUpstream() - SessionOverhead
	cfg := SessionConfig{PSK: "dns-carrier-psk", Cipher: "chacha20", MTU: mtu}

	// Server transport binds an ephemeral UDP port (stands in for :53); the client dials it
	// directly (standing in for a recursive resolver forwarding to our authoritative NS).
	srvT, srvAddr, err := NewDNSServerTransport("127.0.0.1:0", codec)
	if err != nil {
		t.Fatal(err)
	}

	srvCh := make(chan net.Conn, 1)
	go func() {
		c, serr := ServeSession(srvT, cfg)
		if serr != nil {
			t.Errorf("ServeSession: %v", serr)
			srvCh <- nil
			return
		}
		srvCh <- c
	}()

	cliT, err := NewDNSClientTransport(srvAddr.String(), codec)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer cli.Close()

	const payloadSize = 8 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = cli.Write(payload) }()

	srv := <-srvCh
	if srv == nil {
		t.Fatal("server session failed")
	}
	defer srv.Close()

	go func() { // server echoes full-duplex
		buf := make([]byte, 4096)
		for {
			n, rerr := srv.Read(buf)
			if rerr != nil {
				return
			}
			if _, werr := srv.Write(buf[:n]); werr != nil {
				return
			}
		}
	}()

	got := make([]byte, payloadSize)
	readDone := make(chan error, 1)
	go func() {
		off := 0
		buf := make([]byte, 4096)
		for off < len(got) {
			n, rerr := cli.Read(buf)
			if rerr != nil {
				readDone <- rerr
				return
			}
			copy(got[off:], buf[:n])
			off += n
		}
		readDone <- nil
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("timed out: DNS-tunnelled session did not converge")
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch: DNS-tunnelled stream corrupted data")
	}
}
