// This file implements anti-replay protection for the core carriers. Every
// crypto-sealed frame carries an authenticated (session, seq) pair in its nonce
// (see crypto.Sealer): seq strictly increases within a sender's process and
// session changes when the sender restarts. A receiver rejects any frame whose
// seq it has already seen (or that is too old to track), which stops an attacker
// from capturing a valid frame and replaying it — the attack that would
// otherwise let a captured datagram rebind the UDP peer or re-inject a packet.
//
// The window is the standard IPsec-style sliding bitmap of the last 64 sequence
// numbers. It resets when the peer's session id changes, which is what lets a
// legitimately restarted peer (new random prefix, counter back to 1) reconnect.
package packet

const replayWindow = 64

// replayGuard tracks the highest sequence accepted for the current peer session
// plus a bitmap of the preceding replayWindow-1 sequences. It is safe for
// concurrent use by a single receive loop (the only caller), but the mutex-free
// design relies on ok() not being called from two goroutines at once; the core
// carriers each drive it from exactly one reader goroutine.
type replayGuard struct {
	haveSession bool
	session     uint64
	top         uint64 // highest seq accepted so far
	bits        uint64 // bit i set => seq (top-i) already seen
}

// ok reports whether a frame with the given (session, seq) is fresh, and records
// it. A new session id adopts and resets the window (peer restart / first
// frame). Duplicates and frames older than the window are rejected.
func (g *replayGuard) ok(session, seq uint64) bool {
	if !g.haveSession || session != g.session {
		g.haveSession = true
		g.session = session
		g.top = seq
		g.bits = 1
		return true
	}
	if seq > g.top {
		shift := seq - g.top
		if shift >= replayWindow {
			g.bits = 1
		} else {
			g.bits = (g.bits << shift) | 1
		}
		g.top = seq
		return true
	}
	offset := g.top - seq
	if offset >= replayWindow {
		return false // too old to prove it is not a replay
	}
	mask := uint64(1) << offset
	if g.bits&mask != 0 {
		return false // already seen
	}
	g.bits |= mask
	return true
}
