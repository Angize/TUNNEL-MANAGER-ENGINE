package packet

import (
	"encoding/binary"
	"testing"
)

// fecDataShard builds one FEC data-shard wire packet for block `blk` with geometry (n,k), count=1,
// idx=0, and a 2-byte shard. A count=1 data shard pads (n-1) known-zero shards so the block reaches
// present==n immediately and triggers d.codec(n,k) — the exact path that caches a Reed-Solomon codec.
func fecDataShard(blk uint32, n, k int) []byte {
	pkt := make([]byte, fecHdrLen+2)
	pkt[0] = fecTypeData
	binary.BigEndian.PutUint32(pkt[1:5], blk)
	pkt[5] = 0 // idx
	pkt[6] = byte(n)
	pkt[7] = byte(k)
	pkt[8] = 1 // count
	binary.BigEndian.PutUint16(pkt[9:11], 2)
	return pkt
}

// TestFecDecoderCodecCap is the regression test for the pre-auth memory-exhaustion DoS: fecDecoder
// caches a Reed-Solomon codec per distinct (n,k), input runs before peer auth, and nothing budgeted
// the codec objects — so a hostile peer spraying unique (n,k) headers could pin an unbounded set of
// GF(256) matrices. The codecs cache must now stay bounded by fecMaxCodecs regardless of how many
// distinct geometries are thrown at it.
func TestFecDecoderCodecCap(t *testing.T) {
	d := newFecDecoder(func([]byte) {})
	blk := uint32(0)
	// Sweep a wide range of valid (n,k) geometries (n+k<=256, n>=2 so count=1<n reaches present==n).
	for n := 2; n <= 250; n++ {
		for k := 1; k <= 250 && n+k <= 256; k++ {
			d.input(fecDataShard(blk, n, k))
			blk++
			if blk > 4000 { // plenty past the cap to prove it holds
				break
			}
		}
		if blk > 4000 {
			break
		}
	}
	d.mu.Lock()
	got := len(d.codecs)
	d.mu.Unlock()
	if got > fecMaxCodecs {
		t.Fatalf("fecDecoder.codecs grew to %d past the cap %d — pre-auth memory-exhaustion DoS not bounded", got, fecMaxCodecs)
	}
	t.Logf("fec codec cap held: %d distinct (n,k) geometries sprayed, codecs cache bounded at %d (cap %d)", blk, got, fecMaxCodecs)
}
