package packet

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// PeerPool rotates a client's DESTINATION endpoint (or, as a second instance, its SOURCE IP) across a
// list of candidates, so a single blocked IP does not kill the tunnel: a dead endpoint (the handshake
// never completes, or the carrier keeps dying young) is BURNED out of rotation and the pool advances to
// the next live one; a proactive timer also rotates on a schedule. This is the direct-transport analogue
// of the ws edge pool — it works at the dial/peer layer, before any transport framing, so tcp/udp/raw/
// flux all drive it the same way by swapping the endpoint they use.
//
// Health is a three-state FSM (healthy → suspect → dead) exactly like the ws edge pool, not a one-shot
// burn: a failing endpoint becomes SUSPECT (pulled from rotation, retested on an exponential backoff) and
// only DEAD after it fails every backoff step; a merely temporary block therefore heals itself with no
// rebuild. Because the direct transports have no cheap out-of-band prober (a TLS handshake is what the ws
// pool retests with; udp/raw/flux have no equivalent), the "retest" here is re-admission: once a burned
// endpoint's backoff elapses it becomes DUE and the live data plane tries it again on the next rotation
// (proactive tick or failover) — the data plane itself is the probe. A "probe now" pulls every backoff
// forward so a lifted block is picked up at once.
//
// The pool never dead-ends: when nothing is healthy or due it falls back to the least-bad endpoint
// (soonest retest, suspect preferred over dead) so a transient outage that trips every candidate still
// keeps trying instead of stranding the tunnel. An operator can also PIN a specific endpoint (current()
// forces it until it lands or a short TTL lapses) to switch by hand, like the ws pool's per-edge select.
//
// The health primitives (healthRec, stateSuspect/stateDead, suspectBackoff, deadRetest, pinTTL,
// healthStatus) are shared with the ws edge pool (ws_pool.go, same package) so both pools behave and
// report identically.
type PeerPool struct {
	mu         sync.Mutex
	writeMu    sync.Mutex            // serializes the status file write+rename so concurrent writers don't race the shared .tmp
	addrs      []string              // candidate endpoints ("ip" or "ip:port"), in operator order
	health     map[string]*healthRec // absent == healthy; only suspect/dead entries are tracked
	cur        int                   // index of the active endpoint
	autoBurn   bool                  // burn a failing endpoint (vs. only rotate past it)
	rotate     time.Duration         // proactive rotation interval (0 = failover-only)
	statusPath string                // status file the panel reads (empty = off; also gates the pin cmd file)
	pinKey     string                // operator-pinned endpoint: current() forces it until pinUntil
	pinUntil   int64                 // unix time the pin is honoured until; after it, normal rotation resumes
	now        func() int64          // injectable clock (unix seconds); overridden in tests
}

// NewPeerPool builds a pool from the candidate endpoints. addrs must be non-empty (the caller only
// builds a pool when rotation is on with >1 endpoint; a 1-endpoint pool is harmless — it never
// rotates). rotate is the proactive interval; autoBurn drops a failing endpoint from rotation.
func NewPeerPool(addrs []string, autoBurn bool, rotate time.Duration, statusPath string) *PeerPool {
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	p := &PeerPool{addrs: cp, health: map[string]*healthRec{}, autoBurn: autoBurn, rotate: rotate,
		statusPath: statusPath, now: func() int64 { return time.Now().Unix() }}
	p.writeStatus() // publish the initial state so the panel sees the pool immediately
	return p
}

// current returns the active endpoint (never empty for a non-empty pool). It prefers a fully-HEALTHY
// endpoint (scanning forward from cur for variety), then a DUE burned one (its backoff elapsed — the
// live data plane retries it), then the least-bad. A fresh pin forces the pinned endpoint. current()
// commits cur to what it returns, so a subsequent fail() burns the endpoint that was actually used.
func (p *PeerPool) current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentLocked()
}

func (p *PeerPool) currentLocked() string {
	if p.pinKey != "" {
		if p.now() < p.pinUntil {
			for idx, a := range p.addrs {
				if a == p.pinKey {
					p.cur = idx
					return a
				}
			}
			p.pinKey, p.pinUntil = "", 0 // pinned endpoint was removed from the pool -> forget it
		} else {
			p.pinKey, p.pinUntil = "", 0 // expired -> resume normal rotation
		}
	}
	n := len(p.addrs)
	now := p.now()
	// Pass 1: a fully-healthy endpoint, scanning forward from cur (consecutive picks vary).
	for k := 0; k < n; k++ {
		idx := (p.cur + k) % n
		if p.health[p.addrs[idx]] == nil {
			p.cur = idx
			return p.addrs[idx]
		}
	}
	// Pass 2: none healthy — a DUE burned endpoint (its retest time arrived) gets a live retry.
	for k := 0; k < n; k++ {
		idx := (p.cur + k) % n
		if r := p.health[p.addrs[idx]]; r != nil && r.nextRetest <= now {
			p.cur = idx
			return p.addrs[idx]
		}
	}
	// Pass 3: nothing healthy or due — the least-bad endpoint (never dead-end).
	p.cur = p.bestIdxLocked(-1)
	return p.addrs[p.cur]
}

// size is the number of endpoints in the pool. It is fixed at construction, so no lock is needed.
func (p *PeerPool) size() int { return len(p.addrs) }

// tierLocked ranks an endpoint for the least-bad fallback: 0 healthy, 1 suspect, 2 dead, with its
// nextRetest as the tiebreak within a tier. Caller holds the lock.
func (p *PeerPool) tierLocked(addr string) (tier int, next int64) {
	r := p.health[addr]
	if r == nil {
		return 0, 0
	}
	if r.state == stateDead {
		return 2, r.nextRetest
	}
	return 1, r.nextRetest
}

// bestIdxLocked returns the index of the least-bad endpoint (healthy < suspect < dead, soonest
// nextRetest breaking ties), optionally excluding one index (so fail() always MOVES off the endpoint
// it just burned). Caller holds the lock; addrs is non-empty.
func (p *PeerPool) bestIdxLocked(except int) int {
	best := -1
	var bt int
	var bn int64
	for i := range p.addrs {
		if i == except {
			continue
		}
		t, n := p.tierLocked(p.addrs[i])
		if best == -1 || t < bt || (t == bt && n < bn) {
			best, bt, bn = i, t, n
		}
	}
	if best == -1 { // every candidate was excluded (single-endpoint pool) — stay put
		return except
	}
	return best
}

// burnLocked moves the endpoint's health FSM on a failure: healthy → suspect (scheduled +30s), or, if
// it is already tracked (a due endpoint we retried live that failed again), one step further down the
// backoff toward dead. A no-op axis when auto-burn is off. Caller holds the lock.
func (p *PeerPool) burnLocked(addr string) {
	r := p.health[addr]
	if r == nil {
		p.health[addr] = &healthRec{state: stateSuspect, nextRetest: p.now() + suspectBackoff[0]}
		return
	}
	p.failRetestLocked(r)
}

// failRetestLocked reschedules a tracked endpoint after a failed (re)try: a suspect walks the backoff
// list; running off its end drops it to dead; a dead endpoint stays dead on the slow interval. Same
// schedule the ws edge pool uses. Caller holds the lock.
func (p *PeerPool) failRetestLocked(r *healthRec) {
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

// advanceFailLocked moves cur OFF the just-failed endpoint to the best next one to try: a healthy
// endpoint if any, else a due burned one, else the least-bad OTHER endpoint (never re-sticks on the
// endpoint we just burned). Caller holds the lock; addrs has >=2 entries.
func (p *PeerPool) advanceFailLocked() {
	n := len(p.addrs)
	now := p.now()
	for k := 1; k <= n; k++ { // healthy, starting past cur so we move off it
		idx := (p.cur + k) % n
		if p.health[p.addrs[idx]] == nil {
			p.cur = idx
			return
		}
	}
	for k := 1; k <= n; k++ { // else a due burned endpoint
		idx := (p.cur + k) % n
		if r := p.health[p.addrs[idx]]; r != nil && r.nextRetest <= now {
			p.cur = idx
			return
		}
	}
	p.cur = p.bestIdxLocked(p.cur) // else least-bad among the others
}

// advanceEligibleLocked moves cur to another ELIGIBLE endpoint (healthy or due) for a proactive rotate,
// returning whether it moved. It never rotates onto a not-yet-due burned endpoint and stays put when no
// other endpoint is eligible (so the proactive timer doesn't tear a healthy connection down for nothing
// when every alternative is blocked). Caller holds the lock; addrs has >=2 entries.
func (p *PeerPool) advanceEligibleLocked() bool {
	n := len(p.addrs)
	now := p.now()
	for k := 1; k <= n; k++ {
		idx := (p.cur + k) % n
		if idx == p.cur {
			break
		}
		if r := p.health[p.addrs[idx]]; r == nil || r.nextRetest <= now {
			p.cur = idx
			return true
		}
	}
	return false
}

// fail reports that the active endpoint looks dead. With auto-burn it is walked down the health FSM
// (healthy→suspect→…→dead); either way the pool advances to the next endpoint to try and returns it
// (plus whether it actually moved).
func (p *PeerPool) fail() (addr string, moved bool) {
	p.mu.Lock()
	// A live operator pin freezes failover ATOMICALLY — checked under the same p.mu that selectEntry
	// takes — so an in-flight fail() racing a just-set pin can't burn or advance off the pinned endpoint
	// (current() forces it until it lands or its TTL lapses). This is the authoritative guard; the
	// rotationController's pinned() check is only a fast path.
	if len(p.addrs) < 2 || p.pinnedLocked() { // nothing to rotate to, or a pin holds it
		a := p.addrs[p.cur]
		p.mu.Unlock()
		return a, false
	}
	prev := p.cur
	if p.autoBurn {
		p.burnLocked(p.addrs[p.cur])
	}
	p.advanceFailLocked()
	a := p.addrs[p.cur]
	moved = p.cur != prev
	p.mu.Unlock()
	p.writeStatus()
	return a, moved
}

// rotateOnce advances to another ELIGIBLE endpoint WITHOUT burning (the proactive-timer path). Returns
// the new endpoint and whether it moved (a 1-endpoint pool, or one where every alternative is burned and
// not yet due, does not move).
func (p *PeerPool) rotateOnce() (addr string, moved bool) {
	p.mu.Lock()
	if len(p.addrs) < 2 || p.pinnedLocked() { // a pin freezes proactive rotation too (atomic under p.mu)
		a := p.addrs[p.cur]
		p.mu.Unlock()
		return a, false
	}
	moved = p.advanceEligibleLocked()
	a := p.addrs[p.cur]
	p.mu.Unlock()
	if moved {
		p.writeStatus()
	}
	return a, moved
}

// succeeded clears the active endpoint's burn after it connects — a live success proves it healthy right
// now, so a transient block heals. Only writes the status file if something changed.
// succeeded clears any health record on the CURRENT endpoint (it just proved good on the data plane).
// Returns the recovered address when it actually cleared a burn/suspect mark (a heal transition), else ""
// — so the carrier can emit a discrete heal event, otherwise a no-op.
func (p *PeerPool) succeeded() string {
	p.mu.Lock()
	a := p.addrs[p.cur]
	changed := p.health[a] != nil
	delete(p.health, a)
	p.mu.Unlock()
	if changed {
		p.writeStatus()
		return a
	}
	return ""
}

// probeAllNow pulls EVERY suspect/dead endpoint's retest forward to now, so the next rotation (or the
// operator's manual switch) re-admits it immediately instead of waiting out the backoff — a lifted block
// heals at once. Backs the panel's "probe now" control (delivered as a signal that carries no key).
func (p *PeerPool) probeAllNow() {
	p.mu.Lock()
	now := p.now()
	for _, r := range p.health {
		r.nextRetest = now
	}
	p.mu.Unlock()
	p.writeStatus()
}

// selectEntry PINS a specific endpoint as the active one: current() forces it until the carrier lands on
// it (pinApplied clears the pin) or pinTTL elapses with no land — whichever comes first. So it is a
// "jump exactly here now and keep trying until connected" override that survives a transient outage but
// self-releases on success and cannot strand the tunnel on a permanently-dead endpoint. It also clears
// any suspect/dead mark on the chosen endpoint so it gets a clean shot. Returns false if key is unknown.
func (p *PeerPool) selectEntry(key string) bool {
	p.mu.Lock()
	ok := false
	for idx, a := range p.addrs {
		if a == key {
			p.cur = idx
			p.pinKey = key
			p.pinUntil = p.now() + pinTTL
			delete(p.health, key)
			ok = true
			break
		}
	}
	p.mu.Unlock()
	if ok {
		p.writeStatus()
	}
	return ok
}

// pinApplied clears a manual pin once the carrier has ACTUALLY landed on the pinned endpoint, so a pin
// behaves as "jump there and keep retrying until connected" (surviving a transient outage — see pinTTL)
// yet releases the instant it succeeds instead of freezing rotation for the whole window.
func (p *PeerPool) pinApplied(addr string) {
	p.mu.Lock()
	changed := p.pinKey != "" && p.pinKey == addr
	if changed {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

// pinLanded releases a live manual pin because the carrier just handshook successfully — a pin is
// "jump here and keep trying until connected", so a success IS the landing. Single-locked so it can't
// race the pin's own TTL expiry between a check and the clear (the isPinned()+pinApplied(current())
// two-call form could), and it needs no current() call: while pinned, current() forces the pinned
// endpoint, so a success is by definition on it. No-op when no pin is in force.
func (p *PeerPool) pinLanded() {
	p.mu.Lock()
	changed := p.pinnedLocked()
	if changed {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

// releasePin drops a manual pin whose endpoint has been PROVEN blocked (repeated failovers that never
// landed), so current() stops forcing the dead endpoint for the rest of pinTTL and the tunnel recovers on
// a live endpoint at once. A transient outage never reaches here — it heals before the fail threshold —
// so only a decisively-blocked pin ends this way. Writes the status file so the panel reflects the
// released pin immediately. No-op when no pin is set.
func (p *PeerPool) releasePin() {
	p.mu.Lock()
	changed := p.pinKey != ""
	if changed {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

// expirePinIfLapsed clears — and flushes to the status file — a pin whose TTL has just lapsed with no
// landing. current() also drops a lapsed pin, but it runs under the hot lock and cannot write the status
// file, so without this the panel keeps showing a pin the dataplane no longer honours until the next
// unrelated status write. Writes ONLY on the expiry transition, so it is a no-op on the steady 1s tick.
func (p *PeerPool) expirePinIfLapsed() {
	p.mu.Lock()
	lapsed := p.pinKey != "" && p.now() >= p.pinUntil
	if lapsed {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if lapsed {
		p.writeStatus()
	}
}

// pinnedLocked reports whether a manual pin is still in its force window. Caller holds p.mu.
func (p *PeerPool) pinnedLocked() bool { return p.pinKey != "" && p.now() < p.pinUntil }

// isPinned reports whether a manual pin is still in its force window, during which failover and
// proactive rotation are held off so the jump lands exactly. After the window it returns false and
// normal rotation resumes.
func (p *PeerPool) isPinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinnedLocked()
}

// cmdPath is the sidecar file the node writes a "select endpoint" request into (JSON {key}). Empty when
// the pool has no status path (nothing to poll).
func (p *PeerPool) cmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".cmd"
}

// readSelectCmd consumes a pending select-endpoint command (written by the node for the panel's per-IP
// pin button) and returns the requested key. ok=false when none is pending or it is malformed. The file
// is removed once read so a command fires exactly once.
func (p *PeerPool) readSelectCmd() (key string, ok bool) {
	cp := p.cmdPath()
	if cp == "" {
		return "", false
	}
	data, err := os.ReadFile(cp)
	if err != nil {
		return "", false
	}
	os.Remove(cp)
	var c struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(data, &c) != nil || c.Key == "" {
		return "", false
	}
	return c.Key, true
}

// rotationController couples a client carrier's DESTINATION pool with an optional SOURCE pool and
// centralizes the failover/proactive policy, so every carrier (udp/tcp/raw/flux) drives rotation
// identically instead of re-deriving it. The carrier supplies its own rotate funcs (which actually swap
// the peer / the source IP); the controller only decides WHEN to call them.
//
// Policy: on a dead peer, burn+advance the destination; once the destination pool has cycled through
// every endpoint against the current source (destRot reaches the pool size), advance the source too, so
// a blocked source IP is walked off after its destinations are exhausted. A source-only pool (no dest
// pool) just advances the source. The proactive timer moves both pools together. An operator pin on
// either pool FREEZES both failover and proactive rotation until it lands or its TTL lapses, so the
// manual switch is not fought by auto-rotation.
type rotationController struct {
	dst, src *PeerPool
	destRot  int
	pinFails int // consecutive proven-dead rounds while a pin is in force -> auto-release at pinFailRelease
	rotate   time.Duration
	rotateAt time.Time
}

func newRotationController(dst, src *PeerPool) *rotationController {
	c := &rotationController{dst: dst, src: src}
	if dst != nil {
		c.rotate = dst.rotate
	}
	if src != nil && src.rotate > c.rotate {
		c.rotate = src.rotate
	}
	if c.rotate > 0 {
		c.rotateAt = time.Now().Add(c.rotate)
	}
	return c
}

// active reports whether any rotation is wired (either pool present).
func (c *rotationController) active() bool { return c != nil && (c.dst != nil || c.src != nil) }

// pinned reports whether either pool currently holds an operator pin (rotation is frozen).
func (c *rotationController) pinned() bool {
	return (c.dst != nil && c.dst.isPinned()) || (c.src != nil && c.src.isPinned())
}

// fail is called when the current peer looks dead. rotDst/rotSrc are the carrier's swap funcs. While an
// operator pin is in force it is a no-op — current() forces the pinned endpoint until it lands or lapses.
func (c *rotationController) fail(rotDst, rotSrc func(proactive bool)) {
	if c.pinned() {
		// A pinned endpoint proven blocked auto-releases so the tunnel recovers NOW instead of freezing on
		// it for the rest of pinTTL — the datagram/direct analogue of the ws pool's releasePinLocked. Each
		// call here is already a proven-dead round (peerFailThreshold retransmits, or a full clear-mode
		// staleness window, with no session), so a transient blip never reaches even one round; only after
		// pinFailRelease decisive rounds do we drop the pin and fall through to normal failover this call.
		c.pinFails++
		if c.pinFails < pinFailRelease {
			return
		}
		c.pinFails = 0
		if c.dst != nil {
			c.dst.releasePin()
		}
		if c.src != nil {
			c.src.releasePin()
		}
		// pins cleared — fall through and burn+advance off the blocked endpoint this round
	} else {
		c.pinFails = 0 // not pinned -> reset so a later pin starts its release count fresh
	}
	if c.dst != nil {
		rotDst(false)
		c.destRot++
		if c.src != nil && c.dst.size() > 0 && c.destRot >= c.dst.size() {
			rotSrc(false) // every destination tried against this source — move the source
			c.destRot = 0
		}
		return
	}
	if c.src != nil {
		rotSrc(false)
	}
}

// success clears any transient burns after the carrier handshakes, resets the dest-cycle counter, and
// releases a manual pin that has now landed (the carrier is live on the pinned endpoint).
// success marks both pools good and returns the dst/src addresses that RECOVERED from a burn this call
// (empty when nothing healed), so the carrier can surface a discrete heal event.
func (c *rotationController) success() (dstHealed, srcHealed string) {
	c.destRot = 0
	c.pinFails = 0 // a live success (the pin landed, or the endpoint healed) resets the release count
	if c.dst != nil {
		dstHealed = c.dst.succeeded()
		c.dst.pinLanded() // atomically release a pin that has now landed (no-op when unpinned)
	}
	if c.src != nil {
		srcHealed = c.src.succeeded()
		c.src.pinLanded()
	}
	return
}

// proactive fires the timed rotation of BOTH pools when due (a signal-free moving target on each side).
// Held off while a pin is in force so the manual switch is not overridden.
func (c *rotationController) proactive(rotDst, rotSrc func(proactive bool), now time.Time) {
	if c.rotate <= 0 || c.rotateAt.IsZero() || !now.After(c.rotateAt) {
		return
	}
	if c.pinned() {
		c.rotateAt = now.Add(c.rotate) // keep the schedule ticking; just skip this beat
		return
	}
	if c.dst != nil {
		rotDst(true)
	}
	if c.src != nil {
		rotSrc(true)
	}
	c.destRot = 0 // a timed source move restarts the dest cycle (the "all dests tried" count is per-source)
	c.rotateAt = now.Add(c.rotate)
}

// pollPins reads a pending pin command for each pool and, when one is present, pins the requested
// endpoint and calls the carrier's apply func (which re-points the live dataplane at the newly-pinned
// endpoint via the pool's current()). Carriers run this on a ~1s ticker so a manual switch is prompt.
func (c *rotationController) pollPins(applyDst, applySrc func()) {
	if c.dst != nil {
		if key, ok := c.dst.readSelectCmd(); ok && c.dst.selectEntry(key) {
			applyDst()
		}
		c.dst.expirePinIfLapsed() // flush the status file the moment a lapsed pin stops being honoured
	}
	if c.src != nil {
		if key, ok := c.src.readSelectCmd(); ok && c.src.selectEntry(key) {
			applySrc()
		}
		c.src.expirePinIfLapsed()
	}
}

// peerPoolStatus is the pool state written to the status file the node/panel read. Health carries the
// full per-endpoint FSM (state/fails/next_retest); Burned keeps the flat suspect-or-dead list so any
// existing reader keeps working; Pin is the operator-pinned endpoint (empty = none).
type peerPoolStatus struct {
	Active  string         `json:"active"`
	Addrs   []string       `json:"addrs"`
	Burned  []string       `json:"burned"`
	Health  []healthStatus `json:"health"`
	Pin     string         `json:"pin"`
	Updated int64          `json:"updated_unix"`
}

// writeStatus snapshots the pool's live state to statusPath (best effort) so the panel can show which
// endpoint is active, which are burned (and how — suspect vs dead, with the retest countdown), and any
// pin, and can drive the pool via the cmd file. A write error is non-fatal (the dataplane keeps running).
func (p *PeerPool) writeStatus() {
	if p.statusPath == "" {
		return
	}
	// Hold writeMu across BOTH the snapshot and the file write, so concurrent writers can't snapshot in
	// one order and win the write in the other — an older snapshot must never overwrite a newer file
	// (writes are change-driven; there is no periodic re-write to self-correct a stale one). p.mu is
	// always released before any caller reaches writeStatus, so writeMu→p.mu never inverts a lock order.
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	health := make([]healthStatus, 0, len(p.addrs))
	burned := []string{}
	for _, a := range p.addrs {
		hs := healthStatus{Key: a, Kind: "ip", State: "healthy"}
		if r := p.health[a]; r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
			burned = append(burned, a)
		}
		health = append(health, hs)
	}
	st := peerPoolStatus{Active: p.addrs[p.cur], Addrs: append([]string(nil), p.addrs...),
		Burned: burned, Health: health, Pin: p.pinKey, Updated: time.Now().Unix()}
	p.mu.Unlock()
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := p.statusPath + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, p.statusPath) // atomic replace so a reader never sees a half file
	}
}
