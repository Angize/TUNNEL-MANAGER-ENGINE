package packet

import (
	"encoding/json"
	"os"
	"sync"
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
	wasDown bool // a disconnect is pending a matching recovery -> the next connect is a reconnect
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

func (s *coreStatus) write() {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	evs := append([]coreEvent(nil), s.events...) // copy so the marshal runs outside the lock
	active := s.active
	s.mu.Unlock()
	payload := struct {
		Active string      `json:"active"`
		Events []coreEvent `json:"events"`
		TS     int64       `json:"ts"`
	}{Active: active, Events: evs, TS: time.Now().Unix()}
	buf, err := json.Marshal(payload)
	if err != nil {
		return
	}
	s.writeMu.Lock() // serialize writers: the shared ".tmp" path must not be raced by concurrent write() calls
	defer s.writeMu.Unlock()
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, buf, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, s.path) // atomic replace so a reader never sees a half-written file
}
