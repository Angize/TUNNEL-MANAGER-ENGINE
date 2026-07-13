// Edge pool for the ws client: a moving-target rotation over separate clean IP and
// SNI lists. The core cycles (edge-IP × SNI) combinations so no single IP or domain
// stays exposed long enough to be fingerprinted, and tracks per-entry HEALTH with a
// three-state FSM (healthy → suspect → dead) instead of a one-shot burn: a failing
// entry is pulled from rotation and retested on an exponential backoff, so a merely
// TEMPORARY block heals itself without a rebuild. The live state is written to a status
// file the node and panel read to surface and drive the pool.
package packet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
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

// suspectBackoff, deadRetest, dataFailThreshold and dataGoodWindow are the pool health-FSM timings —
// now operator-tunable package vars, defined with their defaults in tuning.go.

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
	mu          sync.Mutex
	writeMu     sync.Mutex // serializes the status file write+rename so concurrent writers don't race the shared .tmp
	ips         []string
	snis        []wsSNIEntry
	ipHealth    map[string]*healthRec // absent == healthy
	sniHealth   map[string]*healthRec // absent == healthy
	i, j        int                   // current ip / sni index
	autoBurn    bool
	statusPath  string
	active      string
	rotDegraded bool           // true once the healthy-IP count fell below 2 (rotation paused); drives the degraded/restored event
	dataFail    map[string]int // per-IP count of consecutive short-lived (data-plane-fault) sessions
	lastGood    int64          // unix time of the last SUSTAINED session on any edge (outage guard)
	events      []coreEvent    // rolling ring of core-observed events (down/burn) for the panel log
	evSeq       int64          // monotonic sequence so the panel can consume each event exactly once
	wasDown     bool           // a genuine carrier down is pending its matching "up" (down/reconnect pairing)
	pinIP       string         // operator-pinned IP: current() forces it until pinUntil (one-shot jump)
	pinSNI      string         // operator-pinned SNI: current() forces it until pinUntil
	pinUntil    int64          // unix time the pin is honoured until; after it, normal rotation resumes
	now         func() int64   // injectable clock (unix seconds); overridden in tests
}

// pinTTL (manual-pin force window, dead-pin self-release cap) is an operator-tunable package var,
// defined with its default in tuning.go.

// coreEvent is one core-observed occurrence surfaced to the panel's system log: the CORE knows the
// real reason a carrier dropped or an edge was burned (it saw the actual error), so instead of the
// panel guessing, it records a stable machine `code` (+ optional detail) the panel maps to text.
type coreEvent struct {
	Seq    int64  `json:"seq"`
	TS     int64  `json:"ts"`
	Kind   string `json:"kind"`   // "down" (carrier dropped) | "up" (reconnected) | "burn" (edge sidelined) | "ech" (ECH self-heal)
	Code   string `json:"code"`   // stable reason category, e.g. ping_timeout / reset / tls / ws_upgrade / throttle
	Detail string `json:"detail"` // optional extra: the edge key, or a short raw-error snippet
}

const coreEventRing = 48 // keep the most recent N events in the status file

// event appends a core-observed event to the ring (newest kept) and flushes the status file so the
// node/panel can surface it. Safe to call from the client loops.
func (p *wsPool) event(kind, code, detail string) {
	p.mu.Lock()
	p.evSeq++
	p.events = append(p.events, coreEvent{Seq: p.evSeq, TS: time.Now().Unix(), Kind: kind, Code: code, Detail: detail})
	if len(p.events) > coreEventRing {
		p.events = p.events[len(p.events)-coreEventRing:]
	}
	p.mu.Unlock()
	p.writeStatus()
}

// down records a genuine carrier drop (NOT an operator pin / proactive rotation) and arms the next
// successful (re)connect — via setActive — to emit a matching "up", so a pool down is always paired
// in the ring like the datagram coreStatus. Callers still classify the reason (code/detail).
func (p *wsPool) down(code, detail string) {
	p.mu.Lock()
	p.wasDown = true
	p.mu.Unlock()
	p.event("down", code, detail)
}

func newWSPool(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) *wsPool {
	p := &wsPool{ips: ips, snis: snis, ipHealth: map[string]*healthRec{}, sniHealth: map[string]*healthRec{},
		dataFail: map[string]int{}, autoBurn: autoBurn, statusPath: statusPath, now: func() int64 { return time.Now().Unix() }}
	p.writeStatus()
	return p
}

// dataSuccess records a SUSTAINED session on ip: it clears the IP's data-plane fault counter and
// stamps the fleet "something worked recently" clock, which suppresses data-plane burns during a
// whole-server / local outage. Called by the pool client when a carrier lived long enough to be
// considered genuinely healthy.
func (p *wsPool) dataSuccess(ip string) {
	p.mu.Lock()
	delete(p.dataFail, ip)
	p.lastGood = p.now()
	p.mu.Unlock()
}

// dataFailure records a SHORT-lived session on ip — the handshake succeeded but the data plane
// died quickly (throttle / blackhole-after-handshake), which the connect-time prober can't see.
// After dataFailThreshold consecutive short deaths the IP is marked suspect so rotation skips it.
// Guarded to avoid false burns: autoBurn on; a healthy alternative IP exists (never strand the
// pool); and a good session happened recently (so a server-side/local outage, where every edge
// dies fast, does not burn the whole pool). Data-plane suspects start on a LONGER backoff, since
// the retest can confirm reachability but not throughput — we must not rush a still-throttled
// edge back into rotation.
func (p *wsPool) dataFailure(ip string) {
	if !p.autoBurn {
		return
	}
	p.mu.Lock()
	burned := false
	recentGood := p.lastGood > 0 && p.now()-p.lastGood < dataGoodWindow
	hasAlt := false
	for _, o := range p.ips {
		if o != ip && p.ipHealth[o] == nil {
			hasAlt = true
			break
		}
	}
	if recentGood && hasAlt {
		p.dataFail[ip]++
		if p.dataFail[ip] >= dataFailThreshold && p.ipHealth[ip] == nil {
			p.ipHealth[ip] = &healthRec{state: stateSuspect, nextRetest: p.now() + suspectStep(2)}
			p.dataFail[ip] = 0
			burned = true
		}
	}
	p.mu.Unlock()
	if burned {
		p.event("burn", "throttle", "ip:"+ip) // handshake-OK-but-data-dead: throttled/blackholed
		p.reassessRotation()                  // this burn may have left only one healthy edge -> rotation paused
	}
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
	// A manual pin is a ONE-SHOT exact jump: while it is fresh (within pinTTL) current() FORCES the
	// chosen axis, so the jump — and any warm-standby promotion during it — lands on EXACTLY that
	// edge, never a neighbour. Once the pin expires it is cleared and normal rotation resumes; the
	// active edge simply stays put (no self-triggered re-dial) until the next proactive rotation.
	if p.pinIP != "" || p.pinSNI != "" {
		if p.now() < p.pinUntil {
			ip := p.resolvePinIPLocked()
			sni := p.resolvePinSNILocked()
			return ip, sni, true
		}
		p.pinIP, p.pinSNI, p.pinUntil = "", "", 0 // expired -> resume normal rotation
	}
	n := len(p.ips) * len(p.snis)
	for k := 0; k < n; k++ {
		ip := p.ips[p.i%len(p.ips)]
		sni := p.snis[p.j%len(p.snis)]
		if p.ipHealth[ip] == nil && p.sniHealth[sni.host] == nil {
			return ip, sni, true
		}
		p.stepLocked()
	}
	ip := p.bestIPLocked()
	sni := p.bestSNILocked()
	return ip, sni, true
}

// updateECH replaces the stored ECHConfigList for the pool SNI matching host with the fresh key the
// edge returned (RetryConfigList) after an in-band self-heal. Persisting it means the NEXT reconnect
// presents the fresh key directly, so the stale-key rejection — and its self-heal event — does not
// recur on every reconnect until the panel's periodic refresh rebuilds the core. Returns true only
// when the stored key actually changed, giving the caller a transition gate (emit the event once per
// rotation, not per reconnect; concurrent healers converge — only the first sees a change).
func (p *wsPool) updateECH(host string, ech []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.snis {
		if p.snis[i].host == host {
			if bytes.Equal(p.snis[i].ech, ech) {
				return false
			}
			p.snis[i].ech = ech
			return true
		}
	}
	return false
}

// activeLabel builds the status-file "active edge" string for an (ip, sni) combo.
func activeLabel(ip, host string) string { return ip + " · " + host }

// setActive records the edge the client is ACTUALLY carrying data on right now, for the status
// file's live "active edge" (and the panel's auto-switch log). current() is intentionally NOT the
// place for this: it is also called to pick a warm STANDBY's edge, so letting it set p.active would
// make the file show the standby instead of the live carrier. Only the real active/promoted carrier
// calls this (from the one dial loop goroutine); an empty combo is ignored so a not-yet-connected
// state never blanks a good active. Flushes the status file so the node/panel see the switch.
func (p *wsPool) setActive(combo string) {
	if combo == "" {
		return
	}
	p.mu.Lock()
	changed := p.active != combo
	p.active = combo
	pending := p.wasDown // a genuine down is awaiting its matching recovery
	p.wasDown = false
	p.mu.Unlock()
	if pending {
		p.event("up", "reconnect", combo) // recovered after a real drop; event() flushes the status file
	} else if changed {
		p.writeStatus()
	}
}

// resolvePinIPLocked returns the IP current() should use: the pinned one (absolute) if it still
// exists, else a healthy-preferred choice for the free axis (and the stale pin is dropped). Caller
// holds the lock.
func (p *wsPool) resolvePinIPLocked() string {
	if p.pinIP != "" {
		for _, ip := range p.ips {
			if ip == p.pinIP {
				return ip
			}
		}
		p.pinIP = "" // pinned IP was removed from the pool -> forget it
	}
	return p.healthyOrBestIPLocked()
}

func (p *wsPool) resolvePinSNILocked() wsSNIEntry {
	if p.pinSNI != "" {
		for _, s := range p.snis {
			if s.host == p.pinSNI {
				return s
			}
		}
		p.pinSNI = ""
	}
	return p.healthyOrBestSNILocked()
}

// healthyOrBestIPLocked returns the first healthy IP, else the least-bad one. Caller holds the lock.
func (p *wsPool) healthyOrBestIPLocked() string {
	for _, ip := range p.ips {
		if p.ipHealth[ip] == nil {
			return ip
		}
	}
	return p.bestIPLocked()
}

func (p *wsPool) healthyOrBestSNILocked() wsSNIEntry {
	for _, s := range p.snis {
		if p.sniHealth[s.host] == nil {
			return s
		}
	}
	return p.bestSNILocked()
}

// isPinned reports whether a manual pin is still in its (short) force window, during which
// proactive rotation is held off so the jump lands exactly. After the window it returns false
// and normal rotation resumes.
func (p *wsPool) isPinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return (p.pinIP != "" || p.pinSNI != "") && p.now() < p.pinUntil
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
func (p *wsPool) markSuspect(kind, key, reason string) {
	if !p.autoBurn {
		return
	}
	p.mu.Lock()
	m := p.healthMap(kind)
	fresh := m[key] == nil
	if fresh {
		m[key] = &healthRec{state: stateSuspect, nextRetest: p.now() + suspectBackoff[0]}
	}
	p.mu.Unlock()
	if fresh {
		p.event("burn", reason, kind+":"+key) // only log the transition into suspect, not repeats
	}
	p.writeStatus()
	if fresh && kind == "ip" {
		p.reassessRotation()
	}
}

// reassessRotation emits a ONE-SHOT event when the pool crosses the "can it still rotate its IP axis?"
// boundary. IP rotation needs >=2 HEALTHY ip endpoints; when a burn/dead leaves only one, the tunnel
// silently stops switching edges (current() keeps returning the sole healthy IP), which reads in the
// log as "rotation stopped". Surface that transition ("degraded") and its recovery ("restored") so the
// operator knows WHY the rotation log went quiet. No-op for a single-ip pool (it never rotated) or when
// the boundary has not moved since the last call. Call after any ip-health transition; it is idempotent.
func (p *wsPool) reassessRotation() {
	p.mu.Lock()
	if len(p.ips) < 2 {
		p.mu.Unlock()
		return
	}
	healthy := 0
	for _, ip := range p.ips {
		if p.ipHealth[ip] == nil {
			healthy++
		}
	}
	degraded := healthy < 2
	if degraded == p.rotDegraded {
		p.mu.Unlock()
		return
	}
	p.rotDegraded = degraded
	p.mu.Unlock()
	detail := strconv.Itoa(healthy) + "/" + strconv.Itoa(len(p.ips))
	if degraded {
		p.event("pool", "degraded", detail) // only one healthy edge left — rotation is paused
	} else {
		p.event("pool", "restored", detail) // a second edge recovered — rotation can resume
	}
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
		p.reassessRotation()
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
	if success {
		// A background probe recovered a sidelined edge/SNI (suspect|dead -> healthy). Emit a discrete
		// heal event so the operator sees the self-heal in the log, not just a silent status-file flip.
		p.event("heal", "retest", kind+":"+key) // event() also writes the status file
	} else {
		p.writeStatus()
	}
	if kind == "ip" {
		p.reassessRotation() // a recovered/dead ip may have crossed the "can still rotate" boundary
	}
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

// selectEntry PINS a specific edge as the active one on its axis: current() forces the chosen edge
// until the carrier actually lands on it (pinApplied clears the pin) or pinTTL elapses with no
// land — whichever comes first. So it is a "jump exactly here now and keep trying until connected"
// override that survives a transient outage but self-releases on success (auto-rotation may then
// drift off it) and on a dead edge. It also clears any suspect/dead mark on the chosen entry so it
// gets a clean shot. Returns false if the key is unknown.
func (p *wsPool) selectEntry(kind, key string) bool {
	p.mu.Lock()
	ok := false
	if kind == "sni" {
		for idx, s := range p.snis {
			if s.host == key {
				p.j = idx
				p.pinSNI = key
				delete(p.sniHealth, key)
				ok = true
				break
			}
		}
	} else {
		for idx, ip := range p.ips {
			if ip == key {
				p.i = idx
				p.pinIP = key
				delete(p.ipHealth, key)
				ok = true
				break
			}
		}
	}
	if ok {
		p.pinUntil = p.now() + pinTTL // force the exact edge until it lands (pinApplied) or the window lapses
	}
	p.mu.Unlock()
	if ok {
		p.writeStatus()
	}
	return ok
}

// pinApplied clears a manual pin once the carrier has ACTUALLY landed on the pinned edge, so a pin
// behaves as "jump there and keep retrying until connected" (surviving a transient outage — see
// pinTTL) yet releases the instant it succeeds instead of freezing rotation for the whole window.
// Each axis is cleared independently: an IP-only pin releases when the live IP matches, likewise SNI.
func (p *wsPool) pinApplied(ip, host string) {
	p.mu.Lock()
	changed := false
	if p.pinIP != "" && p.pinIP == ip {
		p.pinIP = ""
		changed = true
	}
	if p.pinSNI != "" && p.pinSNI == host {
		p.pinSNI = ""
		changed = true
	}
	if p.pinIP == "" && p.pinSNI == "" {
		p.pinUntil = 0
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
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
	// Hold writeMu across BOTH the snapshot and the file write, so two concurrent writers can't snapshot
	// in one order and win the write in the reverse order — an older snapshot must never overwrite a
	// newer file (writes are change-driven; there is no periodic re-write to self-correct a stale one).
	// p.mu is always released before any caller reaches writeStatus, so writeMu→p.mu never inverts.
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
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
	evs := append([]coreEvent(nil), p.events...) // copy so the marshal runs outside the lock
	st := struct {
		Active     string         `json:"active"`
		BurnedIPs  []string       `json:"burned_ips"`
		BurnedSNIs []string       `json:"burned_snis"`
		Health     []healthStatus `json:"health"`
		Events     []coreEvent    `json:"events"`
		PinIP      string         `json:"pin_ip"`
		PinSNI     string         `json:"pin_sni"`
		TS         int64          `json:"ts"`
	}{Active: p.active, BurnedIPs: burnedIPs, BurnedSNIs: burnedSNIs, Health: health, Events: evs, PinIP: p.pinIP, PinSNI: p.pinSNI, TS: time.Now().Unix()}
	p.mu.Unlock()
	if data, err := json.Marshal(st); err == nil {
		// writeMu already held across the snapshot above (serializes writers AND orders snapshot->write).
		tmp := p.statusPath + ".tmp"
		if os.WriteFile(tmp, data, 0o644) == nil {
			_ = os.Rename(tmp, p.statusPath) // atomic replace so a reader never sees a half file
		}
	}
}
