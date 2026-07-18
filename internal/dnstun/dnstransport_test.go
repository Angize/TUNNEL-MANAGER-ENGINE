package dnstun

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// startLossyRelay stands in for a marginal domestic resolver: it forwards each datagram (client->server
// and server->client) only with probability passRate, dropping the rest. It returns its front address
// for the client to point at. Independent PRNGs per direction keep it goroutine-safe.
func startLossyRelay(t *testing.T, server *net.UDPAddr, passRate float64, seed int64) string {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp", nil, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = front.Close(); _ = back.Close() })

	var mu sync.Mutex
	var client *net.UDPAddr

	go func() { // client -> server
		rng := mrand.New(mrand.NewSource(seed))
		buf := make([]byte, dnsReadBuf)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = from
			mu.Unlock()
			if rng.Float64() < passRate {
				_, _ = back.Write(buf[:n])
			}
		}
	}()
	go func() { // server -> client
		rng := mrand.New(mrand.NewSource(seed + 1))
		buf := make([]byte, dnsReadBuf)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			c := client
			mu.Unlock()
			if c != nil && rng.Float64() < passRate {
				_, _ = front.WriteToUDP(buf[:n], c)
			}
		}
	}()
	return front.LocalAddr().String()
}

// TestDNSCarrierSurvivesLossyResolver is the hardening proof: with a resolver that drops ~40% of
// datagrams in each direction (as the domestic smart-DNS resolvers this carrier must use do), the
// session must still converge and move data — carried by the per-query nonce, the reply-on-init hold
// (so the handshake needs one surviving round-trip, not two), and KCP retransmission.
func TestDNSCarrierSurvivesLossyResolver(t *testing.T) {
	origPoll, origTO, origHold := pollInterval, queryTimeout, serverHold
	pollInterval, queryTimeout, serverHold = 3*time.Millisecond, 300*time.Millisecond, 5*time.Millisecond
	defer func() { pollInterval, queryTimeout, serverHold = origPoll, origTO, origHold }()

	codec, err := NewCodec("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	mtu := codec.MaxUpstream() - SessionOverhead
	cfg := SessionConfig{PSK: "psk", Cipher: "chacha20", MTU: mtu}

	srvT, srvAddr, err := NewDNSServerTransport("127.0.0.1:0", codec)
	if err != nil {
		t.Fatal(err)
	}
	relay := startLossyRelay(t, srvAddr.(*net.UDPAddr), 0.6, 1)

	srvCh := make(chan net.Conn, 1)
	go func() {
		c, e := ServeSession(srvT, cfg)
		if e != nil {
			t.Errorf("ServeSession: %v", e)
			srvCh <- nil
			return
		}
		srvCh <- c
	}()

	cliT, err := NewDNSClientTransport([]string{relay}, codec)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := DialSession(cliT, cfg)
	if err != nil {
		t.Fatalf("DialSession over a lossy resolver: %v", err)
	}
	defer cli.Close()

	// Write BEFORE receiving the server conn: the client's first KCP datagram is what unblocks the
	// server's AcceptKCP (and thus ServeSession); waiting on srvCh first would deadlock.
	payload := []byte("hardened DNS carrier surviving a lossy smart-DNS resolver")
	go func() { _, _ = cli.Write(payload) }()

	srv := <-srvCh
	if srv == nil {
		t.Fatal("server session failed")
	}
	defer srv.Close()

	go func() { // server echoes
		buf := make([]byte, 2048)
		for {
			n, e := srv.Read(buf)
			if e != nil {
				return
			}
			if _, e := srv.Write(buf[:n]); e != nil {
				return
			}
		}
	}()

	got := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() {
		off, buf := 0, make([]byte, 2048)
		for off < len(got) {
			n, e := cli.Read(buf)
			if e != nil {
				readDone <- e
				return
			}
			copy(got[off:], buf[:n])
			off += n
		}
		readDone <- nil
	}()

	select {
	case e := <-readDone:
		if e != nil {
			t.Fatalf("read echo over lossy resolver: %v", e)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("timed out: hardened DNS carrier did not converge over a lossy resolver")
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch over lossy resolver")
	}
}

// TestDNSClientRotatesResolvers verifies the client spreads its queries across ALL configured
// resolvers (round-robin), so heavy loss on any one is covered by the others. Three blackhole
// listeners (they never answer) each must receive at least one query.
func TestDNSClientRotatesResolvers(t *testing.T) {
	origPoll, origTO := pollInterval, queryTimeout
	pollInterval, queryTimeout = 2*time.Millisecond, 25*time.Millisecond
	defer func() { pollInterval, queryTimeout = origPoll, origTO }()

	codec, err := NewCodec("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	counts := make([]atomic.Int32, 3)
	for i := range counts {
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		addrs = append(addrs, pc.LocalAddr().String())
		go func(pc *net.UDPConn, cnt *atomic.Int32) {
			b := make([]byte, dnsReadBuf)
			for {
				if _, _, e := pc.ReadFromUDP(b); e != nil {
					return
				}
				cnt.Add(1)
			}
		}(pc, &counts[i])
	}

	tr, err := NewDNSClientTransport(addrs, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	time.Sleep(600 * time.Millisecond) // several poll rotations
	for i := range counts {
		if counts[i].Load() == 0 {
			t.Errorf("resolver %d received no query — client did not rotate across all resolvers", i)
		}
	}
}

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
	qname, err := codec.EncodeName(payload, newNonce())
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
	origPoll, origTO, origHold := pollInterval, queryTimeout, serverHold
	pollInterval, queryTimeout, serverHold = 3*time.Millisecond, 2*time.Second, 5*time.Millisecond
	defer func() { pollInterval, queryTimeout, serverHold = origPoll, origTO, origHold }()

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

	cliT, err := NewDNSClientTransport([]string{srvAddr.String()}, codec)
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
