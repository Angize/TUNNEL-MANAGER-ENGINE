package dnstun

import (
	"errors"
	"net"
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
)

const dnsReadBuf = 1500

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

// parseQuery extracts the transaction id and question name from a query (ignores responses).
func parseQuery(buf []byte) (id uint16, name string, ok bool) {
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil || h.Response {
		return 0, "", false
	}
	q, err := p.Question()
	if err != nil {
		return 0, "", false
	}
	return h.ID, q.Name.String(), true
}

func buildResponseTXT(id uint16, qname string, txt []string) ([]byte, error) {
	n, err := dnsmessage.NewName(qname)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.TXTResource{TXT: txt},
		}},
	}
	return msg.Pack()
}

// ---- client transport (WireTransport) ----

// dnsClient is the client-side WireTransport: it ships each outgoing datagram as a DNS query to a
// recursive resolver and returns downstream datagrams carried back in the responses. It polls even
// when idle so the server can push downstream data (a poll is a bare-zone query with no payload).
type dnsClient struct {
	conn     *net.UDPConn
	codec    *Codec
	outbound chan []byte
	inbound  chan []byte
	closed   chan struct{}
	pollDone chan struct{} // closed when pollLoop has fully exited
	once     sync.Once
	qid      atomic.Uint32
}

// NewDNSClientTransport dials the resolver (host:port, typically a domestic recursive resolver on
// :53) and starts the poll loop. codec encodes datagrams into queries under the delegated zone.
func NewDNSClientTransport(resolverAddr string, codec *Codec) (WireTransport, error) {
	if _, _, err := net.SplitHostPort(resolverAddr); err != nil {
		resolverAddr = net.JoinHostPort(resolverAddr, "53") // default the resolver port to 53
	}
	ra, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, err
	}
	c := &dnsClient{
		conn:     conn,
		codec:    codec,
		outbound: make(chan []byte, sendQueueSize),
		inbound:  make(chan []byte, recvQueueSize),
		closed:   make(chan struct{}),
		pollDone: make(chan struct{}),
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
// bare-zone poll after pollInterval — and delivers the downstream datagram from the response.
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
	name, err := c.codec.EncodeName(up)
	if err != nil {
		return
	}
	id := uint16(c.qid.Add(1))
	query, err := buildQuery(id, name)
	if err != nil {
		return
	}
	if _, err := c.conn.Write(query); err != nil {
		return
	}
	buf := make([]byte, dnsReadBuf)
	deadline := time.Now().Add(queryTimeout)
	for {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return
		}
		n, err := c.conn.Read(buf)
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
}

// NewDNSServerTransport binds listenAddr (typically ":53") as the authoritative responder for the
// delegated zone and starts serving. It returns the transport and the bound address.
func NewDNSServerTransport(listenAddr string, codec *Codec) (WireTransport, net.Addr, error) {
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
	}
	go s.serveLoop()
	return s, conn.LocalAddr(), nil
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
		id, qname, ok := parseQuery(buf[:n])
		if !ok {
			continue
		}
		data, derr := s.codec.DecodeName(qname)
		if derr != nil {
			continue // not under our zone / malformed
		}
		if len(data) > 0 {
			select {
			case s.upstream <- data:
			case <-s.closed:
				return
			default: // full: drop, kcp-go retransmits
			}
		}
		var down []byte
		select {
		case down = <-s.downstream:
		default: // nothing to push this round
		}
		resp, berr := buildResponseTXT(id, qname, s.codec.EncodeTXT(down))
		if berr != nil {
			continue
		}
		_, _ = s.conn.WriteToUDP(resp, addr)
	}
}
