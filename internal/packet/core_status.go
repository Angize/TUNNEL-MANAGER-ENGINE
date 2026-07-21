package packet

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// coreStatus is a lightweight status-file writer + event ring for the connectionless datagram
// transports (udp / raw / flux). They have no ws edge pool, but a client still wants to surface
// PRECISE, core-observed events to the node/panel system log: a self-heal re-handshake (the peer
// most likely restarted / went silent) and the recovery that follows. It writes the SAME status
// JSON shape the ws pool does (an events ring + a ts), so the node's edge-status reader consumes it
// unchanged; the pool-only fields (active health / burned lists / pin) are simply absent. Only the
// CLIENT wires one up (via SetStatusPath); on the server, and before wiring, the nil receiver makes
// every method a no-op. Safe for concurrent use.
type coreStatus struct {
	mu      sync.Mutex
	writeMu sync.Mutex // serializes the file write+rename so concurrent writers don't race the shared .tmp path
	path    string
	active  string // short human descriptor of the live carrier, e.g. "udp · 1.2.3.4:443"
	events  []coreEvent
	evSeq   int64
	wasDown bool  // a disconnect is pending a matching recovery -> the next connect is a reconnect
	hb      int64 // unix-seconds of the last authenticated inbound frame (lastRx); a periodic liveness heartbeat
	dw      int64 // this carrier's RESOLVED dead-window in seconds — the single number a reader uses to age hb
}

// hbInterval is how often a client carrier republishes its lastRx heartbeat into the status file, so a
// reader can tell a live-but-idle tunnel (hb advances every keepalive) from a dead one (hb frozen) with
// no ICMP. Kept small relative to keepalive so the freeze becomes visible promptly.
const hbInterval = 5 * time.Second

// heartbeatLoop republishes the carrier's lastRx (unix-seconds) via beat every hbInterval until done
// closes: an immediate publish so a reader sees a heartbeat at startup, then one per tick.
func heartbeatLoop(beat func(int64), lastRx *atomic.Int64, done <-chan struct{}) {
	beat(lastRx.Load() / int64(time.Second))
	t := time.NewTicker(hbInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			beat(lastRx.Load() / int64(time.Second))
		}
	}
}

// heartbeat republishes lastRx into the coreStatus file. A nil status writer (no status_path wired) is a
// no-op, so it is always safe to start for any client. The nil guard stays HERE so a nil status never
// leaves a goroutine ticking forever.
func heartbeat(s *coreStatus, lastRx *atomic.Int64, done <-chan struct{}) {
	if s == nil {
		return
	}
	heartbeatLoop(s.beat, lastRx, done)
}

// heartbeatPool is heartbeat for a ws/xhttp edge pool, whose status file is written by wsPool.writeStatus
// (not coreStatus), so an idle pooled tunnel reads live, not half-open. A nil pool is a no-op.
func heartbeatPool(p *wsPool, lastRx *atomic.Int64, done <-chan struct{}) {
	if p == nil {
		return
	}
	heartbeatLoop(p.beat, lastRx, done)
}

// beat records the latest lastRx (unix-seconds) and flushes the file. lastRx only moves forward (it is
// re-baselined to now on a re-handshake / rotation), so hb is monotonic in practice.
func (s *coreStatus) beat(sec int64) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.hb = sec
	s.mu.Unlock()
	s.write()
}

// setDW publishes this carrier's resolved dead-window (seconds) so a reader ages hb against the SAME
// number the core self-heals on, instead of re-deriving a private multiplier. Called once at Run.
func (s *coreStatus) setDW(secs int64) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.dw = secs
	s.mu.Unlock()
	s.write()
}

// newCoreStatus creates the writer and flushes an initial (empty-ring) file so a reader sees a live
// tunnel immediately rather than a missing file.
func newCoreStatus(path, active string) *coreStatus {
	s := &coreStatus{path: path, active: active}
	s.write()
	return s
}

// event appends one event to the ring (newest kept, capped at coreEventRing) and flushes the file.
func (s *coreStatus) event(kind, code, detail string) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.evSeq++
	s.events = append(s.events, coreEvent{Seq: s.evSeq, TS: time.Now().Unix(), Kind: kind, Code: code, Detail: detail})
	if len(s.events) > coreEventRing {
		s.events = s.events[len(s.events)-coreEventRing:]
	}
	s.mu.Unlock()
	s.write()
}

// down records a disconnect / self-heal trigger with a precise reason and arms the next successful
// connect to be reported as a recovery.
func (s *coreStatus) down(code, detail string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.wasDown = true
	s.mu.Unlock()
	s.event("down", code, detail)
}

// reconnected records a recovery — but ONLY if a disconnect is pending, so the initial connect at
// startup is never mislabelled as a self-heal.
func (s *coreStatus) reconnected(detail string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	pending := s.wasDown
	s.wasDown = false
	s.mu.Unlock()
	if pending {
		s.event("up", "reconnect", detail)
	}
}

// setActive refreshes the live-carrier descriptor (e.g. "udp · 1.2.3.4:443") after a destination
// rotation so the status file's "active" field doesn't go stale. Locks only to swap the field, then
// flushes outside s.mu because write() re-locks mu.
func (s *coreStatus) setActive(a string) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.active = a
	s.mu.Unlock()
	s.write()
}

func (s *coreStatus) write() {
	if s == nil || s.path == "" {
		return
	}
	// Hold writeMu across BOTH the snapshot and the file write so the on-disk write order can never
	// invert the snapshot order: without this, two concurrent write() calls could snapshot in one
	// order but rename in the other, letting an older snapshot clobber a newer status file and drop
	// the latest event until the next event forces a rewrite. Lock order is writeMu->mu (mu released
	// before I/O), matching ws_pool.go's writeStatus so the two never deadlock.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	evs := append([]coreEvent(nil), s.events...) // copy so the marshal runs outside s.mu
	active := s.active
	hb := s.hb
	dw := s.dw
	s.mu.Unlock()
	payload := struct {
		Active string      `json:"active"`
		Events []coreEvent `json:"events"`
		HB     int64       `json:"hb"`
		DW     int64       `json:"dw"`
		TS     int64       `json:"ts"`
	}{Active: active, Events: evs, HB: hb, DW: dw, TS: time.Now().Unix()}
	buf, err := json.Marshal(payload)
	if err != nil {
		return
	}
	writeFileAtomic(s.path, buf, 0o600)
}

// writeFileAtomic writes data to path via a .tmp file + rename, so a reader never sees a half-written
// status file. The single durability primitive shared by all three status writers (coreStatus / peerPool
// / wsPool); each passes its own perm.
func writeFileAtomic(path string, data []byte, perm os.FileMode) {
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, perm) == nil {
		_ = os.Rename(tmp, path)
	}
}

// sessionStaleWindow is the datagram carriers' resolved dead-window: sessionStaleMult×keepalive, floored at
// sessionStaleMinSecs, or the per-tunnel dead_after_secs override. Shared by every datagram carrier's
// deadWin() so sessionStale() and the status heartbeat (setDW) age against the EXACT same window — no
// re-derived multiplier can drift between the three carriers.
func sessionStaleWindow(keepalive time.Duration, deadAfterSecs int) time.Duration {
	def := time.Duration(sessionStaleMult) * keepalive
	if floor := time.Duration(sessionStaleMinSecs) * time.Second; def < floor {
		def = floor
	}
	return deadWindow(keepalive, deadAfterSecs, def)
}

// staleSince reports whether last (unix-nano of the last inbound frame) has aged past window. A zero last
// means "no baseline yet" -> not stale.
func staleSince(last int64, window time.Duration) bool {
	return last != 0 && time.Since(time.Unix(0, last)) > window
}
