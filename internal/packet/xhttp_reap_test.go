package packet

import (
	"io"
	"testing"
)

// TestXhttpWatchdogSparesServedSession locks in the packet-up reap fix. The handshake-window
// watchdog must reap a session whose downstream GET never arrived, but must NOT kill a healthy
// session that IS serving. Before the fix the guard checked s.done (closed only at session END), so
// the watchdog reaped every live packet-up session at handshakeTimeout, flapping the tunnel every 10s.
func TestXhttpWatchdogSparesServedSession(t *testing.T) {
	b := &TCP{xhSessions: map[string]*xhttpSession{}}
	mk := func(sid string) *xhttpSession {
		pr, pw := io.Pipe()
		s := &xhttpSession{upR: pr, upW: pw, done: make(chan struct{}), served: make(chan struct{}), pend: map[uint64][]byte{}}
		b.xhSessions[sid] = s
		return s
	}
	isClosed := func(ch chan struct{}) bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}

	// A session that started serving (GET bound -> served closed) must SURVIVE the watchdog.
	const liveSID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	live := mk(liveSID)
	close(live.served)
	live.reapIfUnserved(b, liveSID)
	if isClosed(live.done) {
		t.Fatal("watchdog reaped a live (served) session")
	}
	b.xhMu.Lock()
	stillThere := b.xhSessions[liveSID] != nil
	b.xhMu.Unlock()
	if !stillThere {
		t.Fatal("live session was removed from the table")
	}

	// A session whose GET never arrived (served still open) must be REAPED.
	const orphanSID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	orphan := mk(orphanSID)
	orphan.reapIfUnserved(b, orphanSID)
	if !isClosed(orphan.done) {
		t.Fatal("watchdog did not reap an unserved orphan session")
	}
	b.xhMu.Lock()
	gone := b.xhSessions[orphanSID] == nil
	b.xhMu.Unlock()
	if !gone {
		t.Fatal("orphan session was not removed from the table")
	}
}
