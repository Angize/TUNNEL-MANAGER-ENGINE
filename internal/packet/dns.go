// DNS-tunnel carrier: L3 packets ride a reliable, AEAD-sealed KCP session that is itself tunnelled
// inside DNS queries and responses (see internal/dnstun). The client polls a recursive resolver;
// the server is an authoritative responder. This is the last-resort carrier for a full
// (protocol+destination) whitelist: the client only ever sends UDP/53 to a DOMESTIC resolver — never
// a packet to the foreign server IP — so a destination whitelist cannot see it, and port 53 is kept
// open because blocking it breaks all name resolution. Unlike raw/flux this uses only ordinary UDP
// sockets, so it is portable (no CAP_NET_RAW / Linux-only build).
package packet

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/dnstun"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	dnsBackoffMin = time.Second
	dnsBackoffMax = 30 * time.Second
	dnsMinMTU     = 40 // a KCP session needs a workable MTU; a very long zone leaves too little
)

// DNS carries L3 packets over a DNS tunnel. It satisfies the core carrier interface (Run/Close).
type DNS struct {
	dev      *tun.Device
	isClient bool
	cfg      dnstun.SessionConfig
	zone     string
	addr     string // client: resolver "host:port"; server: listen address (e.g. ":53")

	mu      sync.Mutex // guards curConn/curT so Close can tear down whatever is live
	curConn net.Conn
	curT    dnstun.WireTransport
	conn    atomic.Pointer[net.Conn] // the live session for the long-lived tun→net loop (nil between sessions)

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newDNS(dev *tun.Device, isClient bool, addr, zone, psk, cipher string) (*DNS, error) {
	codec, err := dnstun.NewCodec(zone)
	if err != nil {
		return nil, err
	}
	mtu := codec.MaxUpstream() - dnstun.SessionOverhead
	if mtu < dnsMinMTU {
		return nil, fmt.Errorf("dns: zone %q leaves too little room per query (mtu=%d, need >=%d)", zone, mtu, dnsMinMTU)
	}
	return &DNS{
		dev: dev, isClient: isClient, zone: zone, addr: addr,
		cfg:     dnstun.SessionConfig{PSK: psk, Cipher: cipher, MTU: mtu},
		closeCh: make(chan struct{}),
	}, nil
}

// DialDNS (client) tunnels through resolverAddr (a recursive resolver "host:port", typically a
// domestic resolver on :53) for the delegated zone.
func DialDNS(dev *tun.Device, resolverAddr, zone, psk, cipher string) (*DNS, error) {
	return newDNS(dev, true, resolverAddr, zone, psk, cipher)
}

// ListenDNS (server) is the authoritative responder for the delegated zone, bound to listenAddr
// (e.g. ":53").
func ListenDNS(dev *tun.Device, listenAddr, zone, psk, cipher string) (*DNS, error) {
	return newDNS(dev, false, listenAddr, zone, psk, cipher)
}

// Run drives the carrier: one long-lived tun→net loop feeds whatever session is live, while the
// main loop (re)establishes a session and pumps net→tun until it dies, then reconnects with backoff.
func (d *DNS) Run() error {
	go d.tunToNet()
	backoff := dnsBackoffMin
	for {
		select {
		case <-d.closeCh:
			return nil
		default:
		}
		conn, err := d.connect()
		if err != nil {
			log.Printf("core/dns: connect: %v", err)
			if d.sleep(backoff) {
				return nil
			}
			backoff = min(backoff*2, dnsBackoffMax)
			continue
		}
		log.Printf("core/dns: session established (%s zone=%s)", d.role(), d.zone)
		backoff = dnsBackoffMin
		d.conn.Store(&conn)
		d.netToTun(conn) // blocks until the session dies
		d.conn.Store(nil)
		d.clearLive()
		_ = conn.Close()
		if d.isDone() {
			return nil
		}
	}
}

// connect creates a fresh transport and session for one attempt, recording both under the lock so
// Close can tear them down. A fresh transport per attempt gives the server a clean :53 bind and the
// client a fresh resolver socket on every reconnect.
func (d *DNS) connect() (net.Conn, error) {
	codec, err := dnstun.NewCodec(d.zone)
	if err != nil {
		return nil, err
	}
	var t dnstun.WireTransport
	if d.isClient {
		t, err = dnstun.NewDNSClientTransport(d.addr, codec)
	} else {
		t, _, err = dnstun.NewDNSServerTransport(d.addr, codec)
	}
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.isClosed() {
		d.mu.Unlock()
		_ = t.Close()
		return nil, net.ErrClosed
	}
	d.curT = t
	d.mu.Unlock()

	var conn net.Conn
	if d.isClient {
		conn, err = dnstun.DialSession(t, d.cfg)
	} else {
		conn, err = dnstun.ServeSession(t, d.cfg) // blocks until a client establishes
	}
	if err != nil {
		// DialSession/ServeSession already closed t on error.
		d.mu.Lock()
		d.curT = nil
		d.mu.Unlock()
		return nil, err
	}
	d.mu.Lock()
	d.curConn = conn
	d.mu.Unlock()
	return conn, nil
}

func (d *DNS) clearLive() {
	d.mu.Lock()
	d.curConn = nil
	d.curT = nil
	d.mu.Unlock()
}

// tunToNet is long-lived: it reads L3 packets and writes them to whatever session is currently live,
// dropping when there is none (the peer retransmits at L4). It ends only when the TUN device closes.
func (d *DNS) tunToNet() {
	buf := make([]byte, maxDatagram)
	for {
		n, err := d.dev.Read(buf)
		if err != nil {
			return // device closed: carrier shutting down
		}
		cp := d.conn.Load()
		if cp == nil {
			continue // no session yet / between sessions — drop
		}
		if err := dnstun.WritePacket(*cp, buf[:n]); err != nil {
			// session down; drop this packet — Run's netToTun will observe the death and reconnect
		}
	}
}

// netToTun pumps one session's inbound packets into the TUN until the session dies.
func (d *DNS) netToTun(conn net.Conn) {
	for {
		pkt, err := dnstun.ReadPacket(conn)
		if err != nil {
			return // session dead -> reconnect
		}
		if _, err := d.dev.Write(pkt); err != nil {
			log.Printf("core/dns: tun write: %v", err)
			return
		}
	}
}

// Close stops the carrier: it signals shutdown and tears down whatever session/transport is live,
// which unblocks netToTun (via the session) and the transport loops.
func (d *DNS) Close() error {
	d.closeOnce.Do(func() { close(d.closeCh) })
	d.mu.Lock()
	conn, t := d.curConn, d.curT
	d.mu.Unlock()
	if conn != nil {
		_ = conn.Close() // also closes its transport
	} else if t != nil {
		_ = t.Close() // no session yet (e.g. server awaiting a client): stop the transport loops
	}
	return nil
}

func (d *DNS) sleep(dur time.Duration) (closed bool) {
	select {
	case <-d.closeCh:
		return true
	case <-time.After(dur):
		return false
	}
}

func (d *DNS) isDone() bool {
	select {
	case <-d.closeCh:
		return true
	default:
		return false
	}
}

func (d *DNS) isClosed() bool { return d.isDone() }

func (d *DNS) role() string {
	if d.isClient {
		return "client"
	}
	return "server"
}
