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

// Client pipelining. The client keeps multiple queries in flight instead of one-at-a-time, so
// throughput becomes ~window×payload/RTT instead of ~1 datagram/RTT — decisive on a high-latency
// resolver path. Vars so tests can lower them.
var (
	pipelineWindow  = 16 // max queries in flight at once (also caps the per-non-live-frame work)
	idleTarget      = 2  // nonce-only polls kept in flight when no transfer is active (bounds idle footprint)
	sweepInterval   = 500 * time.Millisecond
	collapseEmpties = 24 // consecutive empty replies before the window collapses back to idleTarget
)

// serverWorkers bounds the server's concurrent long-poll replies so a burst of pipelined client
// queries doesn't serialize behind each other's serverHold. >= a client's pipelineWindow.
const serverWorkers = 24

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

// parseMsgQuestion parses a DNS message's header + first question, returning (id, name, type). ok is
// false for a malformed message or one whose direction doesn't match wantResponse (query vs response).
func parseMsgQuestion(buf []byte, wantResponse bool) (id uint16, name string, qtype dnsmessage.Type, ok bool) {
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil || h.Response != wantResponse {
		return 0, "", 0, false
	}
	q, err := p.Question()
	if err != nil {
		return 0, "", 0, false
	}
	return h.ID, q.Name.String(), q.Type, true
}

// parseQuery extracts the transaction id, question name and type from a query (ignores responses).
func parseQuery(buf []byte) (id uint16, name string, qtype dnsmessage.Type, ok bool) {
	return parseMsgQuestion(buf, false)
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
	once      sync.Once
	qid       atomic.Uint32 // fallback DNS transaction-id source when a crypto/rand read fails

	// Pipelining state. inflight maps a live query's DNS id to its deadline + the nonce label the
	// reply must echo (matching by id AND nonce keeps the off-path anti-spoof strength of the old
	// one-id-at-a-time loop). slots is a counting semaphore of spare in-flight capacity (starts full);
	// the invariant |inflight| + len(slots) == pipelineWindow holds because a slot is acquired before
	// the map insert and released after the delete. active flips the send target between idleTarget
	// and pipelineWindow. wake nudges the sender to refill a just-freed slot. wg joins the 3 loops.
	mu       sync.Mutex
	inflight map[uint16]inflightQuery
	slots    chan struct{}
	active   atomic.Bool
	wake     chan struct{}
	wg       sync.WaitGroup
}

// inflightQuery records one outstanding query: when it expires (so the sweeper can reclaim its slot)
// and the nonce label the reply must echo (so a spoofed answer must guess the id AND the nonce).
type inflightQuery struct {
	deadline time.Time
	nonce    string
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
		inflight:  make(map[uint16]inflightQuery, pipelineWindow),
		slots:     make(chan struct{}, pipelineWindow),
		wake:      make(chan struct{}, 1),
	}
	for i := 0; i < pipelineWindow; i++ {
		c.slots <- struct{}{} // prime the semaphore full: all in-flight capacity is initially spare
	}
	c.wg.Add(3)
	go c.sendLoop()
	go c.recvLoop()
	go c.sweepLoop()
	return c, nil
}

// queueSend / queueRecv hold the WireTransport send/recv bodies shared byte-for-byte by dnsClient and
// dnsServer (they differ only in which queue/closed channels they touch). A full outbound queue drops —
// kcp-go retransmits.
func queueSend(closed <-chan struct{}, q chan<- []byte, d []byte) error {
	select {
	case <-closed:
		return net.ErrClosed
	default:
	}
	buf := append([]byte(nil), d...)
	select {
	case q <- buf:
	default: // full: drop, kcp-go retransmits
	}
	return nil
}

func queueRecv(in <-chan []byte, closed <-chan struct{}) ([]byte, error) {
	select {
	case d := <-in:
		return d, nil
	case <-closed:
		return nil, net.ErrClosed
	}
}

func (c *dnsClient) Send(d []byte) error { return queueSend(c.closed, c.outbound, d) }

func (c *dnsClient) Recv() ([]byte, error) { return queueRecv(c.inbound, c.closed) }

func (c *dnsClient) Close() error {
	c.once.Do(func() {
		close(c.closed)    // unblocks the sender's selects, its slot-acquire, and the sweeper
		_ = c.conn.Close() // unblocks the receiver's ReadFromUDP and any in-flight WriteToUDP
	})
	c.wg.Wait() // join sender + receiver + sweeper so no goroutine outlives Close
	return nil
}

// sendLoop is the client's query pump. It ships a queued upstream datagram the moment one arrives and,
// to keep the pipe primed for downstream, tops the in-flight count up to the current target — idleTarget
// when the tunnel is quiet, pipelineWindow while a transfer is active. It wakes on new upstream data, on
// the receiver freeing a slot, and on a periodic tick (so an idle tunnel still keeps a couple of polls out).
func (c *dnsClient) sendLoop() {
	defer c.wg.Done()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-c.closed:
			return
		case up := <-c.outbound:
			if !c.sendOne(up) { // real upstream data: always send
				return
			}
		case <-c.wake:
			if !c.fill() {
				return
			}
		case <-tick.C:
			if !c.fill() {
				return
			}
		}
	}
}

// fill sends nonce-only polls until the in-flight count reaches the current target. Returns false only
// when the transport closed.
func (c *dnsClient) fill() bool {
	target := idleTarget
	if c.active.Load() {
		target = pipelineWindow
	}
	for c.inflightLen() < target {
		if !c.sendOne(nil) {
			return false
		}
	}
	return true
}

// sendOne acquires an in-flight slot, encodes one query (up==nil is a downstream-only poll), records it
// under a UNIQUE DNS id plus its nonce, and writes it to a round-robin resolver. On any pre-send failure
// it rolls the slot back so a transient error never leaks capacity. Returns false only when the transport
// closed while waiting for a slot.
//
// The 16-bit id is drawn from crypto/rand (predictable ids would let an off-path attacker spoof a matching
// answer); with several queries outstanding it is also redrawn on collision so it stays a unique map key.
func (c *dnsClient) sendOne(up []byte) bool {
	if !c.acquire() {
		return false
	}
	nonce := newNonce()
	name, err := c.codec.EncodeName(up, nonce)
	if err != nil {
		c.release()
		return true
	}
	c.mu.Lock()
	var id uint16
	for {
		var idb [2]byte
		if _, rerr := rand.Read(idb[:]); rerr == nil {
			id = uint16(idb[0])<<8 | uint16(idb[1])
		} else {
			id = uint16(c.qid.Add(1))
		}
		if _, dup := c.inflight[id]; !dup {
			break
		}
	}
	c.inflight[id] = inflightQuery{deadline: time.Now().Add(queryTimeout), nonce: nonce}
	c.mu.Unlock()
	query, err := buildQuery(id, name)
	if err != nil {
		c.dropInflight(id)
		return true
	}
	resolver := c.resolvers[int(c.rr.Add(1)-1)%len(c.resolvers)]
	if _, err := c.conn.WriteToUDP(query, resolver); err != nil {
		c.dropInflight(id)
		return true
	}
	return true
}

// recvLoop reads responses from the shared socket, matches each to an outstanding query by BOTH its DNS
// id and its echoed nonce label (so an off-path spoof must guess both, not just one of up to
// pipelineWindow live ids), frees the slot, delivers the downstream datagram, and tracks activity so the
// window widens on a real transfer and collapses back when it ends.
func (c *dnsClient) recvLoop() {
	defer c.wg.Done()
	buf := make([]byte, dnsReadBuf)
	empties := 0
	for {
		n, _, err := c.conn.ReadFromUDP(buf) // reply may come from any source (anycast/smart-DNS backend)
		if err != nil {
			return // socket closed by Close
		}
		id, qname, ok := responseIDName(buf[:n])
		if !ok {
			continue
		}
		if !c.matchRelease(id, qname) {
			continue // unknown id / nonce mismatch: a stale, foreign, or spoofed answer
		}
		down, derr := parseResponseTXT(buf[:n], id)
		if derr != nil {
			continue
		}
		if len(down) > 0 {
			select {
			case c.inbound <- down:
			case <-c.closed:
				return
			default: // full: drop, kcp-go retransmits
			}
			c.active.Store(true)
			empties = 0
		} else if empties++; empties >= collapseEmpties {
			c.active.Store(false)
			empties = 0
		}
	}
}

// sweepLoop reclaims the slot of any query whose answer never arrived within queryTimeout, so a lost
// query/answer can't permanently drain the window (kcp-go retransmits upstream; polls are re-issued).
func (c *dnsClient) sweepLoop() {
	defer c.wg.Done()
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			now := time.Now()
			freed := 0
			c.mu.Lock()
			for id, e := range c.inflight {
				if now.After(e.deadline) {
					delete(c.inflight, id)
					freed++
				}
			}
			c.mu.Unlock()
			for i := 0; i < freed; i++ {
				c.release()
			}
		}
	}
}

// acquire takes one in-flight slot, returning false if the transport closed while it waited.
func (c *dnsClient) acquire() bool {
	select {
	case <-c.slots:
		return true
	case <-c.closed:
		return false
	}
}

// release returns one in-flight slot (never blocks — a token is only returned for one that was acquired,
// so there is always room) and nudges the sender to refill the freshly-opened slot.
func (c *dnsClient) release() {
	select {
	case c.slots <- struct{}{}:
	default:
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *dnsClient) inflightLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inflight)
}

// matchRelease removes the outstanding query for id and frees its slot, but ONLY if id is live AND the
// reply's echoed nonce matches the one sent (case-insensitively — a 0x20-mixing resolver may re-case the
// name). Deleting-under-lock is the single authority for the release, so a receiver match and a sweeper
// timeout for the same id can never double-free.
func (c *dnsClient) matchRelease(id uint16, qname string) bool {
	c.mu.Lock()
	e, ok := c.inflight[id]
	if ok && strings.EqualFold(nonceLabel(qname), e.nonce) {
		delete(c.inflight, id)
	} else {
		ok = false
	}
	c.mu.Unlock()
	if ok {
		c.release()
	}
	return ok
}

// dropInflight rolls back an in-flight entry whose query never went out, freeing its slot.
func (c *dnsClient) dropInflight(id uint16) {
	c.mu.Lock()
	_, ok := c.inflight[id]
	if ok {
		delete(c.inflight, id)
	}
	c.mu.Unlock()
	if ok {
		c.release()
	}
}

// responseIDName parses a DNS message enough to return its id and question name; ok is false for a
// malformed message or a query (not a response).
func responseIDName(buf []byte) (id uint16, qname string, ok bool) {
	id, qname, _, ok = parseMsgQuestion(buf, true)
	return
}

// nonceLabel returns the leftmost label of a query name (the per-query nonce the client set).
func nonceLabel(qname string) string {
	if i := strings.IndexByte(qname, '.'); i >= 0 {
		return qname[:i]
	}
	return qname
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

	soa dnsmessage.Resource // apex SOA, answered so resolvers see a healthy (not lame) zone
	ns  dnsmessage.Resource // apex NS, likewise
}

// NewDNSServerTransport binds listenAddr (typically ":53") as the authoritative responder for the
// delegated zone and starts serving. It returns the transport and the bound address.
func NewDNSServerTransport(listenAddr string, codec *Codec) (WireTransport, net.Addr, error) {
	_, soa, ns, err := apexRecords(codec.Zone())
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

func (s *dnsServer) Send(d []byte) error { return queueSend(s.closed, s.downstream, d) }

func (s *dnsServer) Recv() ([]byte, error) { return queueRecv(s.upstream, s.closed) }

func (s *dnsServer) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.Close() // unblocks serveLoop's ReadFromUDP
	})
	<-s.serveDone // wait for serveLoop to exit so no goroutine outlives Close
	return nil
}

// serveLoop reads each query and delivers its upstream datagram immediately, then dispatches the reply
// (which may long-poll up to serverHold for a downstream datagram) to a bounded worker pool. Reading is
// thus never blocked by another query's hold, so a client that pipelines many queries at once is answered
// concurrently instead of one-serverHold-at-a-time. Replies go to the query's UDP source — the resolver —
// so a changing resolver address never breaks the session (the identity is the tunnel).
func (s *dnsServer) serveLoop() {
	defer close(s.serveDone)
	sem := make(chan struct{}, serverWorkers)
	var wg sync.WaitGroup
	buf := make([]byte, dnsReadBuf)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			break
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
			default: // full: drop, kcp-go retransmits
			}
		}
		// Attach a downstream datagram to the reply in a worker, so THIS query's serverHold long-poll
		// doesn't stall reading the next pipelined query. Copy addr — ReadFromUDP reuses its return. When
		// the pool is saturated (a flood), reply now WITHOUT holding rather than block the read loop.
		ra := *addr
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func(id uint16, qn dnsmessage.Name, ra net.UDPAddr) {
				defer wg.Done()
				defer func() { <-sem }()
				s.reply(id, qn, &ra)
			}(id, qn, ra)
		default:
			s.replyNoHold(id, qn, addr)
		}
	}
	wg.Wait() // let in-flight replies finish before serveDone signals Close
}

// reply answers one query, briefly long-polling (serverHold) for a downstream datagram so a KCP ack/data
// rides this reply instead of a later poll. A datagram already waiting is taken at once.
func (s *dnsServer) reply(id uint16, qn dnsmessage.Name, addr *net.UDPAddr) {
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
	s.write(id, qn, down, addr)
}

// replyNoHold answers immediately with whatever downstream is already queued (no long-poll), used when
// the worker pool is saturated so the read loop is never blocked.
func (s *dnsServer) replyNoHold(id uint16, qn dnsmessage.Name, addr *net.UDPAddr) {
	var down []byte
	select {
	case down = <-s.downstream:
	default:
	}
	s.write(id, qn, down, addr)
}

// write packs the TXT answer carrying down (empty TXT when nil) and sends it to addr.
func (s *dnsServer) write(id uint16, qn dnsmessage.Name, down []byte, addr *net.UDPAddr) {
	resp, berr := buildResponse(id, qn, dnsmessage.TypeTXT, []dnsmessage.Resource{txtResource(qn, s.codec.EncodeTXT(down))})
	if berr != nil {
		return
	}
	_, _ = s.conn.WriteToUDP(resp, addr)
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
