package main

import (
	"encoding/json"
	"testing"
)

// FuzzConfig hammers the config parse+default+validate pipeline with arbitrary JSON. A node writes
// this file, but a corrupt or hand-edited config must never crash the core on startup — validate()
// and applyDefaults() must reject bad input with an error, never panic (index-out-of-range on an
// empty pool slice, a bad split, etc.). The contract: for ANY input, no panic.
func FuzzConfig(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"role":"client","mode":"packet","profile":"core"}`))
	f.Add([]byte(`{"role":"server","peer_ips":[],"listen_ips":["1.2.3.4:443"]}`))
	f.Add([]byte(`{"role":"client","peer_ips":["1.2.3.4:443","5.6.7.8:443"],"ws_edge_ips":["9.9.9.9"]}`))
	f.Add([]byte(`{"dead_after_secs":999,"ws_rotate_secs":-1,"keepalive_secs":0}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var c Config
		if err := json.Unmarshal(data, &c); err != nil {
			return // not valid JSON — the real loadConfig returns this error, no further processing
		}
		c.applyDefaults()
		_ = c.validate()
	})
}
