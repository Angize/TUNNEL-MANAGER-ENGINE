// Edge pool for the ws client: a moving-target rotation over separate clean IP and
// SNI lists. The core cycles (edge-IP × SNI) combinations so no single IP or domain
// stays exposed long enough to be fingerprinted, and tracks per-entry HEALTH with a
// three-state FSM (healthy → suspect → dead) instead of a one-shot burn: a failing
// entry is pulled from rotation and retested on an exponential backoff, so a merely
// TEMPORARY block heals itself without a rebuild. The live state is written to a status
// file the node and panel read to surface and drive the pool.
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
func DialWSPoolCfg(dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, ips []string, snis []WSPoolSNI, rotate time.Duration, autoBurn bool, statusPath string, xhttp bool, xhMode string, warmStandby bool) (*TCP, error) {
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
	return DialWSPool(dev, keepalive, obfs, cryptoOn, psk, cipher, pool, rotate, xhttp, xhMode, warmStandby)
}

// wsSNIEntry is one fronting domain in the pool with its own ECH config and path.
type wsSNIEntry struct {
	host string
	ech  []byte
	path string
}

// Health FSM states for a pool entry (an IP, or an SNI host). A HEALTHY entry has NO record
// in the health map at all (absence == healthy); only suspect/dead entries are tracked.
const (
	stateSuspect = "suspect" // a probe found it guilty; pulled from rotation; retested on backoff
	stateDead    = "dead"    // failed enough retests; retested only on the slow interval
)

// suspectBackoff is the retest schedule (seconds) for a SUSPECT entry: it enters suspect
// scheduled +30s out, and each FAILED retest walks one step further down the list. Running
// off the end (the 5th failed retest) drops the entry to DEAD.
var suspectBackoff = []int64{30, 60, 120, 300, 600}

// deadRetest is the slow interval (seconds) a DEAD entry is retested on.
const deadRetest int64 = 1800

// healthRec tracks one non-healthy pool entry. fails counts failed retests since it entered
// suspect; nextRetest is the unix time the scheduler may probe it again.
type healthRec struct {
	state      string
	fails      int
	nextRetest int64
}

// wsPool holds the clean IP/SNI lists, the per-entry health FSM, and the active index.
// ipHealth/sniHealth track only the non-healthy entries (absent == healthy). Every change
// is snapshotted to statusPath. The pool is network-free (unit-testable): the prober and the
// retest scheduler live in tcp.go and drive the FSM through these pure methods.
type wsPool struct {
	mu         sync.Mutex
	ips        []string
	snis       []wsSNIEntry
	ipHealth   map[string]*healthRec // absent == healthy
	sniHealth  map[string]*healthRec // absent == healthy
	i, j       int                   // current ip / sni index
	autoBurn   bool
	statusPath string
	active     string
	now        func() int64 // injectable clock (unix seconds); overridden in tests
}

func newWSPool(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) *wsPool {
	p := &wsPool{ips: ips, snis: snis, ipHealth: map[string]*healthRec{}, sniHealth: map[string]*healthRec{},
		autoBurn: autoBurn, statusPath: statusPath, now: func() int64 { return time.Now().Unix() }}
	p.writeStatus()
	return p
}

// healthMap returns the record map for the given axis ("ip" or "sni"). Caller holds the lock.
func (p *wsPool) healthMap(kind string) map[string]*healthRec {
	if kind == "sni" {
		return p.sniHealth
	}
	return p.ipHealth
}

// current returns the active (ip, sni). It prefers a FULLY-HEALTHY combo, scanning forward
// from the current index so consecutive dials rotate for variety. When no combo is fully
// healthy it never dead-ends: it falls back to the least-bad ip and sni (soonest nextRetest,
// suspect preferred over dead) so the tunnel keeps trying while the retest scheduler works
// the blocked entries back to health. ok=false only if the pool has no IPs or no SNIs.
func (p *wsPool) current() (string, wsSNIEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ips) == 0 || len(p.snis) == 0 {
		return "", wsSNIEntry{}, false
	}
	n := len(p.ips) * len(p.snis)
	for k := 0; k < n; k++ {
		ip := p.ips[p.i%len(p.ips)]
		sni := p.snis[p.j%len(p.snis)]
		if p.ipHealth[ip] == nil && p.sniHealth[sni.host] == nil {
			p.active = ip + " · " + sni.host
			return ip, sni, true
		}
		p.stepLocked()
	}
	ip := p.bestIPLocked()
	sni := p.bestSNILocked()
	p.active = ip + " · " + sni.host
	return ip, sni, true
}

// bestIPLocked / bestSNILocked return the least-bad entry for the current() fallback: a
// healthy one if any, else the tracked entry with the soonest nextRetest, preferring suspect
// over dead. Caller holds the lock; the underlying slice is non-empty.
func (p *wsPool) bestIPLocked() string {
	best := p.ips[0]
	bt, bn := p.tierLocked("ip", best)
	for _, ip := range p.ips[1:] {
		if t, n := p.tierLocked("ip", ip); t < bt || (t == bt && n < bn) {
			best, bt, bn = ip, t, n
		}
	}
	return best
}

func (p *wsPool) bestSNILocked() wsSNIEntry {
	best := p.snis[0]
	bt, bn := p.tierLocked("sni", best.host)
	for _, s := range p.snis[1:] {
		if t, n := p.tierLocked("sni", s.host); t < bt || (t == bt && n < bn) {
			best, bt, bn = s, t, n
		}
	}
	return best
}

// tierLocked ranks an entry for the current() fallback: 0 healthy, 1 suspect, 2 dead, with
// its nextRetest as the tiebreak within a tier. Caller holds the lock.
func (p *wsPool) tierLocked(kind, key string) (tier int, next int64) {
	r := p.healthMap(kind)[key]
	if r == nil {
		return 0, 0
	}
	if r.state == stateDead {
		return 2, r.nextRetest
	}
	return 1, r.nextRetest
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

// advance rotates to the next combination (proactive rotation timer / post-failure retry).
func (p *wsPool) advance() {
	p.mu.Lock()
	p.stepLocked()
	p.mu.Unlock()
}

// advanceIP / advanceSNI rotate a single dimension (manual "rotate now, IP only" /
// "rotate now, SNI only" from the panel). current() still skips unhealthy entries, so a
// bump that lands on a suspect/dead one is passed over on the next dial.
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

// markSuspect moves a HEALTHY entry into suspect (out of active rotation, scheduled for a
// +30s retest). A no-op when autoBurn is off (a manual-only pool never auto-sidelines an
// entry) or when the entry is already tracked — a fresh live failure must not reset an
// in-progress backoff; the retest scheduler owns the entry's cadence from here.
func (p *wsPool) markSuspect(kind, key string) {
	if !p.autoBurn {
		return
	}
	p.mu.Lock()
	m := p.healthMap(kind)
	if m[key] == nil {
		m[key] = &healthRec{state: stateSuspect, nextRetest: p.now() + suspectBackoff[0]}
	}
	p.mu.Unlock()
	p.writeStatus()
}

// succeeded clears the health records for a combo that just connected: a live success proves
// both its IP and its SNI healthy right now. Only writes the status file if something changed.
func (p *wsPool) succeeded(ip, host string) {
	p.mu.Lock()
	changed := p.ipHealth[ip] != nil || p.sniHealth[host] != nil
	delete(p.ipHealth, ip)
	delete(p.sniHealth, host)
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

// retestResult feeds a probe outcome for a tracked entry into the FSM: ANY success clears it
// back to healthy; a failure walks the suspect backoff and eventually drops it to dead.
func (p *wsPool) retestResult(kind, key string, success bool) {
	p.mu.Lock()
	m := p.healthMap(kind)
	r := m[key]
	if r == nil { // cleared from under us (e.g. a concurrent live success) — nothing to do
		p.mu.Unlock()
		return
	}
	if success {
		delete(m, key)
	} else {
		p.failRetestLocked(r)
	}
	p.mu.Unlock()
	p.writeStatus()
}

// failRetestLocked reschedules a tracked entry after a FAILED retest. A suspect walks the
// backoff list; running off its end (fails == len) drops it to dead. A dead entry stays dead
// on the slow interval. Caller holds the lock.
func (p *wsPool) failRetestLocked(r *healthRec) {
	now := p.now()
	if r.state == stateDead {
		r.nextRetest = now + deadRetest
		return
	}
	r.fails++
	if r.fails >= len(suspectBackoff) {
		r.state = stateDead
		r.nextRetest = now + deadRetest
		return
	}
	r.nextRetest = now + suspectBackoff[r.fails]
}

// retestSpec is one entry the scheduler should probe now, paired with a partner on the OTHER
// axis to probe it against (a known-healthy partner when one exists, else the current active
// partner) so the probe changes only the entry under test.
type retestSpec struct {
	kind string // "ip" or "sni": which axis the entry belongs to
	key  string
	ip   string     // the IP to dial
	sni  wsSNIEntry // the SNI to present
}

// dueRetests returns the tracked entries whose nextRetest has arrived, each paired with a
// partner to probe against. The scheduler runs one probe per spec and feeds the boolean back
// through retestResult.
func (p *wsPool) dueRetests() []retestSpec {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var out []retestSpec
	for _, ip := range p.ips {
		if r := p.ipHealth[ip]; r != nil && r.nextRetest <= now {
			out = append(out, retestSpec{kind: "ip", key: ip, ip: ip, sni: p.partnerSNILocked()})
		}
	}
	for _, s := range p.snis {
		if r := p.sniHealth[s.host]; r != nil && r.nextRetest <= now {
			out = append(out, retestSpec{kind: "sni", key: s.host, ip: p.partnerIPLocked(), sni: s})
		}
	}
	return out
}

// partnerSNILocked / partnerIPLocked pick a KNOWN-HEALTHY partner to retest an entry against,
// falling back to the currently-selected one when none is healthy. Caller holds the lock.
func (p *wsPool) partnerSNILocked() wsSNIEntry {
	for _, s := range p.snis {
		if p.sniHealth[s.host] == nil {
			return s
		}
	}
	return p.snis[p.j%len(p.snis)]
}

func (p *wsPool) partnerIPLocked() string {
	for _, ip := range p.ips {
		if p.ipHealth[ip] == nil {
			return ip
		}
	}
	return p.ips[p.i%len(p.ips)]
}

// altHealthySNI returns a healthy SNI other than exclude (the differential probe's
// "same IP, different SNI" arm); ok=false when none exists.
func (p *wsPool) altHealthySNI(exclude string) (wsSNIEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.snis {
		if s.host != exclude && p.sniHealth[s.host] == nil {
			return s, true
		}
	}
	return wsSNIEntry{}, false
}

// altHealthyIP returns a healthy IP other than exclude (the differential probe's
// "different IP, same SNI" arm); ok=false when none exists.
func (p *wsPool) altHealthyIP(exclude string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ip := range p.ips {
		if ip != exclude && p.ipHealth[ip] == nil {
			return ip, true
		}
	}
	return "", false
}

// probeNow forces an entry to be retested on the scheduler's next tick (backs a panel/node
// "probe now" control). A no-op for an untracked (healthy) entry.
func (p *wsPool) probeNow(kind, key string) {
	p.mu.Lock()
	if r := p.healthMap(kind)[key]; r != nil {
		r.nextRetest = p.now()
	}
	p.mu.Unlock()
}

// probeAllNow pulls EVERY suspect/dead entry's retest forward to now, so the scheduler
// probes them all on its next tick. Backs the panel's "probe now" control (a signal can't
// carry a specific key, so this sweeps them all — cheap TLS-only probes).
func (p *wsPool) probeAllNow() {
	p.mu.Lock()
	now := p.now()
	for _, r := range p.ipHealth {
		r.nextRetest = now
	}
	for _, r := range p.sniHealth {
		r.nextRetest = now
	}
	p.mu.Unlock()
}

// selectEntry pins a SPECIFIC edge as the active one: it moves the rotation index onto that
// entry and clears any suspect/dead mark on it — the operator explicitly chose it, so give it a
// clean shot (the FSM re-suspects it if it fails again). Returns false if the key is unknown.
func (p *wsPool) selectEntry(kind, key string) bool {
	p.mu.Lock()
	ok := false
	if kind == "sni" {
		for idx, s := range p.snis {
			if s.host == key {
				p.j = idx
				delete(p.sniHealth, key)
				ok = true
				break
			}
		}
	} else {
		for idx, ip := range p.ips {
			if ip == key {
				p.i = idx
				delete(p.ipHealth, key)
				ok = true
				break
			}
		}
	}
	p.mu.Unlock()
	if ok {
		p.writeStatus()
	}
	return ok
}

// cmdPath is the sidecar file the node writes a "select edge" request into (JSON {kind,key}).
// Empty when the pool has no status path (nothing to poll).
func (p *wsPool) cmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".cmd"
}

// readSelectCmd consumes a pending select-edge command (written by the node for the panel's
// per-edge pin button) and returns the requested (kind,key). ok=false when none is pending or
// it is malformed. The file is removed once read so a command fires exactly once.
func (p *wsPool) readSelectCmd() (kind, key string, ok bool) {
	cp := p.cmdPath()
	if cp == "" {
		return "", "", false
	}
	data, err := os.ReadFile(cp)
	if err != nil {
		return "", "", false
	}
	os.Remove(cp)
	var c struct {
		Kind string `json:"kind"`
		Key  string `json:"key"`
	}
	if json.Unmarshal(data, &c) != nil || c.Key == "" {
		return "", "", false
	}
	if c.Kind != "sni" {
		c.Kind = "ip"
	}
	return c.Kind, c.Key, true
}

// healthStatus is one entry's health as published to the status file.
type healthStatus struct {
	Key        string `json:"key"`
	Kind       string `json:"kind"`  // "ip" | "sni"
	State      string `json:"state"` // "healthy" | "suspect" | "dead"
	Fails      int    `json:"fails"`
	NextRetest int64  `json:"next_retest_unix"`
}

// writeStatus snapshots {active, burned_ips, burned_snis, health, ts} to statusPath (best
// effort) so the node/panel can show the live edge and drive the pool. health carries the
// full per-entry FSM state; burned_ips/burned_snis keep the old arrays alive (every
// suspect-or-dead key) so existing readers keep working.
func (p *wsPool) writeStatus() {
	if p.statusPath == "" {
		return
	}
	p.mu.Lock()
	health := make([]healthStatus, 0, len(p.ips)+len(p.snis))
	burnedIPs, burnedSNIs := []string{}, []string{}
	for _, ip := range p.ips {
		hs := healthStatus{Key: ip, Kind: "ip", State: "healthy"}
		if r := p.ipHealth[ip]; r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
			burnedIPs = append(burnedIPs, ip)
		}
		health = append(health, hs)
	}
	for _, s := range p.snis {
		hs := healthStatus{Key: s.host, Kind: "sni", State: "healthy"}
		if r := p.sniHealth[s.host]; r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
			burnedSNIs = append(burnedSNIs, s.host)
		}
		health = append(health, hs)
	}
	sort.Strings(burnedIPs)
	sort.Strings(burnedSNIs)
	st := struct {
		Active     string         `json:"active"`
		BurnedIPs  []string       `json:"burned_ips"`
		BurnedSNIs []string       `json:"burned_snis"`
		Health     []healthStatus `json:"health"`
		TS         int64          `json:"ts"`
	}{Active: p.active, BurnedIPs: burnedIPs, BurnedSNIs: burnedSNIs, Health: health, TS: time.Now().Unix()}
	p.mu.Unlock()
	if data, err := json.Marshal(st); err == nil {
		tmp := p.statusPath + ".tmp"
		if os.WriteFile(tmp, data, 0o644) == nil {
			_ = os.Rename(tmp, p.statusPath) // atomic replace so a reader never sees a half file
		}
	}
}
