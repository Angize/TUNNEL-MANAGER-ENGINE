package dnstun

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSMessageHelpersRoundTrip(t *testing.T) {
	// A query built by the client must parse back to the same id+name on the server, and a TXT
	// response must parse back to the same bytes on the client.
	name := "abcd.ef23.t.example.com."
	q, err := buildQuery(0x1234, name)
	if err != nil {
		t.Fatal(err)
	}
	id, gotName, qtype, ok := parseQuery(q)
	if !ok || id != 0x1234 || gotName != name || qtype != dnsmessage.TypeTXT {
		t.Fatalf("parseQuery = %d,%q,%v,%v want 0x1234,%q,TXT,true", id, gotName, qtype, ok, name)
	}
	qn, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x00, 0x01, 0xff, 0xfe, 'x', 'y'}
	resp, err := buildResponse(0x1234, qn, dnsmessage.TypeTXT, []dnsmessage.Resource{txtResource(qn, []string{string(payload)})})
	if err != nil {
		t.Fatal(err)
	}
	// The authoritative bit must be set (recursive resolvers reject a non-authoritative answer
	// from the zone's own nameserver) and recursion-available must be clear.
	var hp dnsmessage.Parser
	rh, err := hp.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !rh.Authoritative {
		t.Fatal("buildResponse: AA bit not set — resolvers will treat the zone as lame and SERVFAIL")
	}
	if rh.RecursionAvailable {
		t.Fatal("buildResponse: RA bit set on an authoritative response")
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

// buildTypedQuery packs a query for an arbitrary type (the client only ever asks TXT, so the
// helper in production hardcodes it; resolvers probing the zone ask SOA/NS/A/etc.).
func buildTypedQuery(id uint16, name string, qtype dnsmessage.Type) []byte {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		panic(err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	b, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return b
}

// TestDNSServerAuthoritativeBehavior drives the server transport the way a real recursive resolver
// does — probing the zone with SOA/NS/A queries and minimizing intermediate names — and asserts the
// replies are authoritative (AA set), echo the queried type, carry SOA/NS at the apex, and return an
// authoritative NODATA (AA set, no answers) everywhere else. Before the fix the server answered
// every query with a TXT-typed question and no AA bit, so resolvers rejected the zone as lame.
func TestDNSServerAuthoritativeBehavior(t *testing.T) {
	codec, err := NewCodec("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	srvT, srvAddr, err := NewDNSServerTransport("127.0.0.1:0", codec)
	if err != nil {
		t.Fatal(err)
	}
	defer srvT.Close()

	conn, err := net.DialUDP("udp", nil, srvAddr.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ask := func(name string, qtype dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		if _, err := conn.Write(buildTypedQuery(0x4242, name, qtype)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, dnsReadBuf)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("%s %v: no response: %v", name, qtype, err)
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			t.Fatalf("%s %v: unpack: %v", name, qtype, err)
		}
		if !msg.Header.Authoritative {
			t.Fatalf("%s %v: AA bit not set", name, qtype)
		}
		if msg.Header.RecursionAvailable {
			t.Fatalf("%s %v: RA bit set on authoritative reply", name, qtype)
		}
		if len(msg.Questions) != 1 || msg.Questions[0].Type != qtype {
			t.Fatalf("%s %v: question not echoed with queried type: %+v", name, qtype, msg.Questions)
		}
		return msg
	}

	apex := "t.example.com."

	soa := ask(apex, dnsmessage.TypeSOA)
	if len(soa.Answers) != 1 || soa.Answers[0].Header.Type != dnsmessage.TypeSOA {
		t.Fatalf("apex SOA: expected one SOA answer, got %+v", soa.Answers)
	}

	ns := ask(apex, dnsmessage.TypeNS)
	if len(ns.Answers) != 1 || ns.Answers[0].Header.Type != dnsmessage.TypeNS {
		t.Fatalf("apex NS: expected one NS answer, got %+v", ns.Answers)
	}

	// A/NS at the apex or a minimized sub-name that we don't publish: authoritative NODATA, not a
	// referral or SERVFAIL — this keeps a QNAME-minimizing resolver advancing to the TXT query.
	for _, tc := range []struct {
		name  string
		qtype dnsmessage.Type
	}{
		{apex, dnsmessage.TypeA},
		{"sub." + apex, dnsmessage.TypeNS},
		{"sub." + apex, dnsmessage.TypeA},
	} {
		reply := ask(tc.name, tc.qtype)
		if len(reply.Answers) != 0 {
			t.Fatalf("%s %v: expected NODATA (0 answers), got %+v", tc.name, tc.qtype, reply.Answers)
		}
	}

	// A non-TXT query for a name outside the zone is dropped, not answered: an authoritative server
	// must not claim a zone it doesn't serve.
	if _, err := conn.Write(buildTypedQuery(0x4242, "elsewhere.example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := conn.Read(make([]byte, dnsReadBuf)); err == nil {
		t.Fatalf("out-of-zone A query got a %d-byte response; expected silent drop", n)
	}

	// A TXT query still carries the tunnel: it delivers its upstream datagram and gets a TXT reply.
	payload := []byte("hello-upstream")
	qname, err := codec.EncodeName(payload)
	if err != nil {
		t.Fatal(err)
	}
	txt := ask(qname, dnsmessage.TypeTXT)
	if len(txt.Answers) != 1 || txt.Answers[0].Header.Type != dnsmessage.TypeTXT {
		t.Fatalf("tunnel TXT: expected one TXT answer, got %+v", txt.Answers)
	}
	got, err := srvT.Recv()
	if err != nil {
		t.Fatalf("Recv upstream: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("upstream datagram: got %q want %q", got, payload)
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
