package dnstun

import (
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNS transport timing. Throughput is irrelevant for this carrier; these bound the poll rate and
// how long a client waits for a resolver to answer before giving up on one exchange (kcp-go
// retransmits anything lost, so a dropped query costs only a round-trip, never data).
var (
	pollInterval = 40 * time.Millisecond // idle downstream-poll cadence (var so tests can lower it)
	queryTimeout = 3 * time.Second       // per-query wait for the resolver's answer
	// serverHold is how long the server briefly withholds a response, waiting for a downstream datagram
	// to attach to THIS reply (a long-poll). It lets the handshake response ride the very query that
	// carried the init — and every KCP ack ride the query that prompted it — instead of a later poll,
	// so a session converges in far fewer round-trips. That is decisive on a lossy or answer-mangling
	// resolver where each extra round-trip is another chance to fail. Kept well under queryTimeout and a
	// recursive resolver's own upstream timeout. A var so tests can lower it.
	serverHold = 150 * time.Millisecond
)

const dnsReadBuf = 1500

// newNonce returns a fresh nonceLen-char lowercase-base32 label for one query. It is the leftmost
// label of every query name, making each name unique so a recursive resolver never serves a query
// from cache or coalesces two — every poll and every retransmit reaches our authoritative server.
// crypto/rand is overkill for cache-busting but the volume is ~one label per round-trip, so cost is
// irrelevant; on the vanishingly rare read error the zero-value bytes still yield a valid label.
func newNonce() string {
	var b [(nonceLen*5 + 7) / 8]byte // enough entropy bytes to base32 to >= nonceLen chars
	_, _ = rand.Read(b[:])
	return lowB32.EncodeToString(b[:])[:nonceLen]
}

// ---- DNS message helpers (x/net/dnsmessage) ----

func buildQuery(id uint16, name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

// parseResponseTXT verifies the response matches wantID and concatenates its TXT answer bytes.
func parseResponseTXT(buf []byte, wantID uint16) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil {
		return nil, err
	}
	if h.ID != wantID || !h.Response {
		return nil, errors.New("dns: response id/flag mismatch")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []byte
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		if ah.Type == dnsmessage.TypeTXT {
			txt, terr := p.TXTResource()
			if terr != nil {
				return nil, terr
			}
			for _, s := range txt.TXT {
				out = append(out, s...)
			}
		} else if err := p.SkipAnswer(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseQuery extracts the transaction id, question name and type from a query (ignores responses).
func parseQuery(buf []byte) (id uint16, name string, qtype dnsmessage.Type, ok bool) {
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil || h.Response {
		return 0, "", 0, false
	}
	q, err := p.Question()
	if err != nil {
		return 0, "", 0, false
	}
	return h.ID, q.Name.String(), q.Type, true
}

// buildResponse assembles an authoritative reply: the AA bit is set, RA is cleared, the question is
// echoed with the type actually queried, and the given answer records are attached. A recursive
// resolver querying a zone's own nameserver iteratively (RD=0) requires AA on the answer — without
// it the delegation looks lame and the lookup SERVFAILs, so this bit is what makes the carrier work
// through real resolvers rather than only a direct-to-server dig.
func buildResponse(id uint16, qname dnsmessage.Name, qtype dnsmessage.Type, answers []dnsmessage.Resource) ([]byte, error) {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}},
		Answers:   answers,
	}
	return msg.Pack()
}

// txtResource wraps downstream character-strings as a single TXT answer record under name. TTL is
// left at 0 as cache hygiene (the per-query nonce already makes every name unique, so nothing repeats).
func txtResource(name dnsmessage.Name, txt []string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.TXTResource{TXT: txt},
	}
}

// ---- client transport (WireTransport) ----

// dnsClient is the client-side WireTransport: it ships each outgoing datagram as a DNS query to a
// recursive resolver and returns downstream datagrams carried back in the responses. It polls even
// when idle so the server can push downstream data (a poll is a nonce-only query with no payload).
//
// The socket is UNCONNECTED (net.ListenUDP, not DialUDP): a query goes to a resolver picked
// round-robin from resolvers, and a reply is accepted from ANY source address. Both matter on the
// lossy, hostile paths this carrier runs on — round-robin spreads each query across every configured
// resolver so heavy loss on one is covered by the others, and accepting replies from any source keeps
// working with anycast / smart-DNS resolvers whose answer arrives from a different backend IP than the
// one queried (a connected socket would drop those). Answers are matched by DNS id, not source.
type dnsClient struct {
	conn      *net.UDPConn
	resolvers []*net.UDPAddr
	rr        atomic.Uint32 // round-robin cursor over resolvers
	codec     *Codec
	outbound  chan []byte
	inbound   chan []byte
	closed    chan struct{}
	pollDone  chan struct{} // closed when pollLoop has fully exited
	once      sync.Once
	qid       atomic.Uint32
}

// NewDNSClientTransport resolves the recursive resolvers (each "host" or "host:port"; :53 default),
// opens one unconnected UDP socket, and starts the poll loop. codec encodes datagrams into queries
// under the delegated zone. At least one usable resolver is required.
func NewDNSClientTransport(resolverAddrs []string, codec *Codec) (WireTransport, error) {
	var resolvers []*net.UDPAddr
	for _, ra := range resolverAddrs {
		ra = strings.TrimSpace(ra)
		if ra == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(ra); err != nil {
			// No port: default to :53. Strip any brackets first so JoinHostPort (which re-brackets a
			// colon-bearing host) doesn't double-bracket a bare "[v6]" into an invalid "[[v6]]:53".
			host := strings.TrimSuffix(strings.TrimPrefix(ra, "["), "]")
			ra = net.JoinHostPort(host, "53")
		}
		ua, err := net.ResolveUDPAddr("udp", ra)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, ua)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("dns: no usable resolver configured")
	}
	laddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	c := &dnsClient{
		conn:      conn,
		resolvers: resolvers,
		codec:     codec,
		outbound:  make(chan []byte, sendQueueSize),
		inbound:   make(chan []byte, recvQueueSize),
		closed:    make(chan struct{}),
		pollDone:  make(chan struct{}),
	}
	go c.pollLoop()
	return c, nil
}

func (c *dnsClient) Send(d []byte) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	buf := append([]byte(nil), d...)
	select {
	case c.outbound <- buf:
	default: // full: drop, kcp-go retransmits
	}
	return nil
}

func (c *dnsClient) Recv() ([]byte, error) {
	select {
	case d := <-c.inbound:
		return d, nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *dnsClient) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close() // unblocks pollLoop's Read
	})
	<-c.pollDone // wait for pollLoop to exit so no goroutine outlives Close
	return nil
}

// pollLoop sends one query per iteration — a queued upstream datagram when available, otherwise a
// nonce-only poll after pollInterval — and delivers the downstream datagram from the response.
func (c *dnsClient) pollLoop() {
	defer close(c.pollDone)
	idle := time.NewTimer(pollInterval)
	defer idle.Stop()
	for {
		var up []byte
		select {
		case <-c.closed:
			return
		case up = <-c.outbound:
		case <-idle.C:
			up = nil // idle: poll for downstream
		}
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(pollInterval)
		c.exchange(up)
	}
}

// exchange runs one query/response. A lost query or timed-out answer is not an error here: kcp-go
// retransmits any upstream datagram, and the downstream slot is retried on the next poll.
func (c *dnsClient) exchange(up []byte) {
	name, err := c.codec.EncodeName(up, newNonce())
	if err != nil {
		return
	}
	id := uint16(c.qid.Add(1))
	query, err := buildQuery(id, name)
	if err != nil {
		return
	}
	resolver := c.resolvers[int(c.rr.Add(1)-1)%len(c.resolvers)]
	if _, err := c.conn.WriteToUDP(query, resolver); err != nil {
		return
	}
	buf := make([]byte, dnsReadBuf)
	deadline := time.Now().Add(queryTimeout)
	for {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return
		}
		n, _, err := c.conn.ReadFromUDP(buf) // reply may come from any source (anycast/smart-DNS backend)
		if err != nil {
			return // timeout or socket closed
		}
		down, derr := parseResponseTXT(buf[:n], id)
		if derr != nil {
			continue // a stale/foreign answer: keep reading until our id or the deadline
		}
		if len(down) > 0 {
			select {
			case c.inbound <- down:
			case <-c.closed:
			default: // full: drop, kcp-go retransmits
			}
		}
		return
	}
}

// ---- server transport (WireTransport) ----

// dnsServer is the server-side WireTransport: an authoritative responder that reads queries, hands
// the upstream datagram (carried in the query name) to the session, and attaches a queued
// downstream datagram to each response. Point-to-point: it serves one client/session.
type dnsServer struct {
	conn       *net.UDPConn
	codec      *Codec
	upstream   chan []byte
	downstream chan []byte
	closed     chan struct{}
	serveDone  chan struct{} // closed when serveLoop has fully exited
	once       sync.Once

	zoneName dnsmessage.Name     // the delegated zone apex, precomputed for question/answer names
	soa      dnsmessage.Resource // apex SOA, answered so resolvers see a healthy (not lame) zone
	ns       dnsmessage.Resource // apex NS, likewise
}

// NewDNSServerTransport binds listenAddr (typically ":53") as the authoritative responder for the
// delegated zone and starts serving. It returns the transport and the bound address.
func NewDNSServerTransport(listenAddr string, codec *Codec) (WireTransport, net.Addr, error) {
	zoneName, soa, ns, err := apexRecords(codec.Zone())
	if err != nil {
		return nil, nil, err
	}
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, nil, err
	}
	s := &dnsServer{
		conn:       conn,
		codec:      codec,
		upstream:   make(chan []byte, recvQueueSize),
		downstream: make(chan []byte, sendQueueSize),
		closed:     make(chan struct{}),
		serveDone:  make(chan struct{}),
		zoneName:   zoneName,
		soa:        soa,
		ns:         ns,
	}
	go s.serveLoop()
	return s, conn.LocalAddr(), nil
}

// apexRecords precomputes the zone-apex name plus its SOA and NS answer records. They point the
// zone at itself (MNAME/NS = apex): the parent delegation already carries the glue that routes
// resolvers here, so these only need to answer the apex probes (SOA/NS) that resolvers make while
// validating the zone — self-reference keeps them well-formed without a second hostname to publish.
// Serial is fixed and MinTTL is 0 (no zone transfers, no negative caching for this carrier).
func apexRecords(zone string) (dnsmessage.Name, dnsmessage.Resource, dnsmessage.Resource, error) {
	zn, err := dnsmessage.NewName(zone)
	if err != nil {
		return dnsmessage.Name{}, dnsmessage.Resource{}, dnsmessage.Resource{}, err
	}
	mbox, err := dnsmessage.NewName("hostmaster." + zone)
	if err != nil {
		mbox = zn // zone too long for the hostmaster. prefix: fall back to the apex as RNAME
	}
	soa := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: zn, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET},
		Body: &dnsmessage.SOAResource{
			NS: zn, MBox: mbox, Serial: 1,
			Refresh: 3600, Retry: 600, Expire: 604800, MinTTL: 0,
		},
	}
	ns := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: zn, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.NSResource{NS: zn},
	}
	return zn, soa, ns, nil
}

func (s *dnsServer) Send(d []byte) error {
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	buf := append([]byte(nil), d...)
	select {
	case s.downstream <- buf:
	default: // full: drop, kcp-go retransmits
	}
	return nil
}

func (s *dnsServer) Recv() ([]byte, error) {
	select {
	case d := <-s.upstream:
		return d, nil
	case <-s.closed:
		return nil, net.ErrClosed
	}
}

func (s *dnsServer) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.Close() // unblocks serveLoop's ReadFromUDP
	})
	<-s.serveDone // wait for serveLoop to exit so no goroutine outlives Close
	return nil
}

// serveLoop reads each query, delivers its upstream datagram, and answers with a queued downstream
// datagram (or an empty TXT when none is waiting). The reply goes to the query's UDP source — the
// resolver — so a changing resolver address never breaks the session (the identity is the tunnel).
func (s *dnsServer) serveLoop() {
	defer close(s.serveDone)
	buf := make([]byte, dnsReadBuf)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		id, qname, qtype, ok := parseQuery(buf[:n])
		if !ok {
			continue
		}
		qn, nerr := dnsmessage.NewName(qname)
		if nerr != nil {
			continue
		}

		// Only TXT queries carry the tunnel. Anything else is a resolver validating or minimizing
		// the delegation (SOA/NS at the apex, or an intermediate A/NS probe); answer in-zone names
		// authoritatively so the zone never looks lame, but never let it touch the session. Names
		// outside the zone are dropped — an authoritative server must not claim what it doesn't serve.
		if qtype != dnsmessage.TypeTXT {
			if !s.underZone(qname) {
				continue
			}
			resp, berr := buildResponse(id, qn, qtype, s.apexAnswers(qname, qtype))
			if berr == nil {
				_, _ = s.conn.WriteToUDP(resp, addr)
			}
			continue
		}

		data, derr := s.codec.DecodeName(qname)
		if derr != nil {
			continue // a TXT query outside our zone / malformed
		}
		if len(data) > 0 {
			select {
			case s.upstream <- data:
			case <-s.closed:
				return
			default: // full: drop, kcp-go retransmits
			}
		}
		// Briefly hold the reply so a downstream datagram (the handshake response, a KCP ack) can ride
		// THIS answer instead of a later poll — see serverHold. A datagram already waiting is taken at
		// once; otherwise we wait up to serverHold and reply empty. A per-query timer (not time.After in
		// the select, which would leak a timer until it fires) keeps the idle path allocation-free enough.
		var down []byte
		select {
		case down = <-s.downstream:
		case <-s.closed:
			return
		default:
			hold := time.NewTimer(serverHold)
			select {
			case down = <-s.downstream:
			case <-hold.C:
			case <-s.closed:
				hold.Stop()
				return
			}
			hold.Stop()
		}
		resp, berr := buildResponse(id, qn, dnsmessage.TypeTXT, []dnsmessage.Resource{txtResource(qn, s.codec.EncodeTXT(down))})
		if berr != nil {
			continue
		}
		_, _ = s.conn.WriteToUDP(resp, addr)
	}
}

// apexAnswers returns the authority records for a non-TXT query: the SOA or NS at the exact zone
// apex, and nothing (an authoritative NODATA, AA set) for every other name or type. NODATA rather
// than silence keeps a QNAME-minimizing resolver moving — it reads "the name exists, no record of
// this type" and proceeds to the real TXT query instead of retrying and giving up.
func (s *dnsServer) apexAnswers(qname string, qtype dnsmessage.Type) []dnsmessage.Resource {
	if !s.isApex(qname) {
		return nil
	}
	switch qtype {
	case dnsmessage.TypeSOA:
		return []dnsmessage.Resource{s.soa}
	case dnsmessage.TypeNS:
		return []dnsmessage.Resource{s.ns}
	}
	return nil
}

// normName lowercases, trims, and ensures a single trailing dot so a query name compares cleanly
// against the codec's fully-qualified zone (case- and trailing-dot-tolerant).
func normName(qname string) string {
	q := strings.ToLower(strings.TrimSpace(qname))
	if !strings.HasSuffix(q, ".") {
		q += "."
	}
	return q
}

// isApex reports whether qname is exactly the delegated zone apex.
func (s *dnsServer) isApex(qname string) bool { return normName(qname) == s.codec.Zone() }

// underZone reports whether qname is the apex or a name beneath it (a real label boundary before the
// zone, so "abt.example.com" is not accepted as under "t.example.com").
func (s *dnsServer) underZone(qname string) bool {
	q := normName(qname)
	return q == s.codec.Zone() || strings.HasSuffix(q, "."+s.codec.Zone())
}
