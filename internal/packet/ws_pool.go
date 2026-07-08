// Edge pool for the ws client: a moving-target rotation over separate clean IP and
// SNI lists. The core cycles (edge-IP × SNI) combinations so no single IP or domain
// stays exposed long enough to be fingerprinted, drops a blocked one from rotation
// (classified by how it failed), and writes its live state to a status file the node
// and panel read to surface and persist the auto-burns.
package packet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// WSPoolSNI is the exported (config) form of a pool SNI passed from main: the domain,
// its base64 ECHConfigList (empty = none), and request path (empty = "/").
type WSPoolSNI struct {
	Host string
	ECH  string
	Path string
}

// DialWSPoolCfg decodes the config's clean IP/SNI lists into a pool and returns a ws
// client that rotates over it. rotate is the proactive-rotation interval.
func DialWSPoolCfg(dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, ips []string, snis []WSPoolSNI, rotate time.Duration, autoBurn bool, statusPath string, xhttp bool, xhMode string) (*TCP, error) {
	entries := make([]wsSNIEntry, 0, len(snis))
	for _, s := range snis {
		var ech []byte
		if s.ECH != "" {
			ech, _ = base64.StdEncoding.DecodeString(s.ECH) // validated in config
		}
		entries = append(entries, wsSNIEntry{host: s.Host, ech: ech, path: s.Path})
	}
	pool := newWSPoolFromCfg(ips, entries, autoBurn, statusPath)
	if pool == nil {
		return nil, errors.New("ws pool: need at least one IP and one SNI")
	}
	return DialWSPool(dev, keepalive, obfs, cryptoOn, psk, cipher, pool, rotate, xhttp, xhMode)
}

// wsSNIEntry is one fronting domain in the pool with its own ECH config and path.
type wsSNIEntry struct {
	host string
	ech  []byte
	path string
}

// burnEvidence is how many distinct partners on the OTHER axis an entry must fail a
// handshake with before an (ambiguous) TLS/WS failure burns it. A single failed combo
// can't tell whether the IP or the SNI is at fault — a throttled edge IP resets the TLS
// handshake exactly like a blocked SNI does — so we wait for corroboration: an IP that
// fails across several SNIs is the culprit; an SNI that fails across several IPs is.
const burnEvidence = 2

// wsPool holds the clean IP/SNI lists, runtime burn tracking, and the active index.
// Auto-burn (when enabled) removes a failing IP or SNI from selection; the burn set
// is snapshotted to statusPath after every change. ipFails/sniFails accumulate the
// per-axis evidence used to attribute an ambiguous handshake failure (see burnEvidence).
type wsPool struct {
	mu         sync.Mutex
	ips        []string
	snis       []wsSNIEntry
	burnedIP   map[string]bool
	burnedSNI  map[string]bool
	ipFails    map[string]map[string]bool // ip  -> distinct SNIs it failed a handshake with
	sniFails   map[string]map[string]bool // sni -> distinct IPs it failed a handshake with
	i, j       int                        // current ip / sni index
	autoBurn   bool
	statusPath string
	active     string
}

func newWSPool(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) *wsPool {
	p := &wsPool{ips: ips, snis: snis, burnedIP: map[string]bool{}, burnedSNI: map[string]bool{},
		ipFails: map[string]map[string]bool{}, sniFails: map[string]map[string]bool{},
		autoBurn: autoBurn, statusPath: statusPath}
	p.writeStatus()
	return p
}

// current returns the active (ip, sni), skipping any burned IP or SNI. ok=false when
// every combination is unusable — the caller then resets the burns for a fresh cycle
// so the tunnel is never permanently dead-ended.
func (p *wsPool) current() (string, wsSNIEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.ips) * len(p.snis)
	for k := 0; k < n; k++ {
		ip := p.ips[p.i%len(p.ips)]
		sni := p.snis[p.j%len(p.snis)]
		if !p.burnedIP[ip] && !p.burnedSNI[sni.host] {
			p.active = ip + " · " + sni.host
			return ip, sni, true
		}
		p.stepLocked()
	}
	return "", wsSNIEntry{}, false
}

// stepLocked advances to the next (ip, sni) combination (caller holds the lock).
func (p *wsPool) stepLocked() {
	p.j++
	if p.j >= len(p.snis) {
		p.j = 0
		p.i++
		if p.i >= len(p.ips) {
			p.i = 0
		}
	}
}

// advance rotates to the next combination (proactive rotation timer).
func (p *wsPool) advance() {
	p.mu.Lock()
	p.stepLocked()
	p.mu.Unlock()
}

// advanceIP / advanceSNI rotate a single dimension (manual "rotate now, IP only" /
// "rotate now, SNI only" from the panel). current() still skips burned entries, so a
// bump that lands on a burned one is passed over on the next dial.
func (p *wsPool) advanceIP() {
	p.mu.Lock()
	if len(p.ips) > 0 {
		p.i = (p.i + 1) % len(p.ips)
	}
	p.mu.Unlock()
}

func (p *wsPool) advanceSNI() {
	p.mu.Lock()
	if len(p.snis) > 0 {
		p.j = (p.j + 1) % len(p.snis)
	}
	p.mu.Unlock()
}

// burnIP/burnSNI drop a failing entry from rotation (when autoBurn is on) and step
// past it. A no-op on autoBurn=off except for advancing, so a manual-only pool still
// rotates away from a dead edge for this attempt without persisting the burn. These are
// the UNAMBIGUOUS burns — burnIP for a TCP-dial failure (the SNI never went on the wire,
// so the IP alone is at fault). Ambiguous TLS/WS failures go through handshakeFailed.
func (p *wsPool) burnIP(ip string) {
	p.mu.Lock()
	if p.autoBurn {
		p.burnIPLocked(ip)
	}
	p.stepLocked()
	p.mu.Unlock()
	p.writeStatus()
}

func (p *wsPool) burnSNI(host string) {
	p.mu.Lock()
	if p.autoBurn {
		p.burnSNILocked(host)
	}
	p.stepLocked()
	p.mu.Unlock()
	p.writeStatus()
}

// burnIPLocked marks an IP burned and drops its blame votes against SNIs: now that the
// IP is known bad, its past handshake failures are no evidence against those domains, so
// they must not push a healthy SNI over the threshold. Caller holds the lock.
func (p *wsPool) burnIPLocked(ip string) {
	p.burnedIP[ip] = true
	for sni := range p.ipFails[ip] {
		if s := p.sniFails[sni]; s != nil {
			delete(s, ip)
		}
	}
	delete(p.ipFails, ip)
}

func (p *wsPool) burnSNILocked(host string) {
	p.burnedSNI[host] = true
	for ip := range p.sniFails[host] {
		if m := p.ipFails[ip]; m != nil {
			delete(m, host)
		}
	}
	delete(p.sniFails, host)
}

// handshakeFailed records a TLS/WS-upgrade failure of a specific (ip, sni) combo. Which
// axis is at fault is ambiguous, so nothing is burned on the first data point: the IP is
// burned only once it has failed across burnEvidence distinct SNIs, the SNI only once it
// has failed across burnEvidence distinct IPs. Until then we rotate on and let the next
// combo corroborate — this is what stops one dead edge IP from burning healthy SNIs.
func (p *wsPool) handshakeFailed(ip, sni string) {
	p.mu.Lock()
	if p.autoBurn {
		if p.ipFails[ip] == nil {
			p.ipFails[ip] = map[string]bool{}
		}
		p.ipFails[ip][sni] = true
		if p.sniFails[sni] == nil {
			p.sniFails[sni] = map[string]bool{}
		}
		p.sniFails[sni][ip] = true
		switch {
		case len(p.ipFails[ip]) >= burnEvidence:
			p.burnIPLocked(ip)
		case len(p.sniFails[sni]) >= burnEvidence:
			p.burnSNILocked(sni)
		}
	}
	p.stepLocked()
	p.mu.Unlock()
	p.writeStatus()
}

// succeeded clears the accumulated blame for a combo that just connected, so a stale
// transient failure never adds up to a false burn later.
func (p *wsPool) succeeded(ip, sni string) {
	p.mu.Lock()
	if m := p.ipFails[ip]; m != nil {
		delete(m, sni)
	}
	if s := p.sniFails[sni]; s != nil {
		delete(s, ip)
	}
	p.mu.Unlock()
}

// resetBurns clears the burn sets — called when the pool is exhausted so a link never
// dead-ends (a temporarily-blocked IP/SNI gets another chance on the next cycle).
func (p *wsPool) resetBurns() {
	p.mu.Lock()
	p.burnedIP = map[string]bool{}
	p.burnedSNI = map[string]bool{}
	p.ipFails = map[string]map[string]bool{}
	p.sniFails = map[string]map[string]bool{}
	p.mu.Unlock()
	p.writeStatus()
}

// writeStatus snapshots {active, burned_ips, burned_snis} to statusPath (best effort)
// so the node/panel can show the live edge and persist auto-burns to the config.
func (p *wsPool) writeStatus() {
	if p.statusPath == "" {
		return
	}
	p.mu.Lock()
	st := struct {
		Active     string   `json:"active"`
		BurnedIPs  []string `json:"burned_ips"`
		BurnedSNIs []string `json:"burned_snis"`
		TS         int64    `json:"ts"`
	}{Active: p.active, BurnedIPs: keysOf(p.burnedIP), BurnedSNIs: keysOf(p.burnedSNI), TS: time.Now().Unix()}
	p.mu.Unlock()
	if data, err := json.Marshal(st); err == nil {
		tmp := p.statusPath + ".tmp"
		if os.WriteFile(tmp, data, 0o644) == nil {
			_ = os.Rename(tmp, p.statusPath) // atomic replace so a reader never sees a half file
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
