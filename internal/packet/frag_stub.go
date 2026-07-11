//go:build !linux

package packet

// writeDisorder falls back to a plain in-order split off Linux, where per-segment IP_TTL control
// isn't wired. The split still helps against a stateless DPI; the disorder desync does not apply.
func (f *fragConn) writeDisorder(p []byte, at int) (int, error) {
	return f.writeSplit(p, at)
}
