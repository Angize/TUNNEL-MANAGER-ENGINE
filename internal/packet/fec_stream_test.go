package packet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// End-to-end wire test: push data frames through the encoder, drop some of every
// block's shards on the "wire", and require the decoder to still deliver every
// original frame exactly once and in order. This exercises the block framing,
// partial-block flush, pad synthesis, and reconstruction together.
func TestFecStreamRecoversUnderLoss(t *testing.T) {
	const n, k = 10, 3

	// frames of varied length (including short ones) to stress the [len:2] wrap + padding.
	frames := make([][]byte, 47)
	for i := range frames {
		frames[i] = make([]byte, 1+(i*37)%400)
		rand.Read(frames[i])
	}

	var got [][]byte
	dec := newFecDecoder(func(f []byte) { got = append(got, append([]byte(nil), f...)) })

	// The wire drops the FIRST loss shards of each block (up to k) — a worst case of
	// consecutive data losses. blockPkts collects one block's packets before we apply loss.
	var blockPkts [][]byte
	blockNo := 0
	flushWithLoss := func() {
		lose := blockNo % (k + 1) // 0..k dropped, cycling
		for i, p := range blockPkts {
			if i < lose {
				continue // dropped on the wire
			}
			dec.input(p)
		}
		blockPkts = nil
		blockNo++
	}

	enc, err := newFecEncoder(n, k, func(pkt []byte) {
		blockPkts = append(blockPkts, append([]byte(nil), pkt...))
	})
	if err != nil {
		t.Fatal(err)
	}
	// Feed frames; every n frames the encoder flushes a full block synchronously
	// (emit appends to blockPkts), which we then push through the lossy wire.
	for i, f := range frames {
		enc.addData(f)
		if (i+1)%n == 0 {
			flushWithLoss()
		}
	}
	// Flush the trailing partial block.
	enc.mu.Lock()
	enc.flushLocked()
	enc.mu.Unlock()
	flushWithLoss()

	if len(got) != len(frames) {
		t.Fatalf("delivered %d frames, want %d", len(got), len(frames))
	}
	for i := range frames {
		if !bytes.Equal(got[i], frames[i]) {
			t.Fatalf("frame %d mismatch: got %d bytes want %d", i, len(got[i]), len(frames[i]))
		}
	}
}

// When a block loses more than k shards it cannot be reconstructed; the decoder must
// simply not deliver that block (no panic, no garbage), and later blocks still work.
func TestFecStreamDropsUnrecoverableBlock(t *testing.T) {
	const n, k = 6, 2
	var got [][]byte
	dec := newFecDecoder(func(f []byte) { got = append(got, append([]byte(nil), f...)) })

	var pkts [][]byte
	enc, _ := newFecEncoder(n, k, func(p []byte) { pkts = append(pkts, append([]byte(nil), p...)) })

	// Block 0: lose 3 shards (> k=2) → unrecoverable.
	for i := 0; i < n; i++ {
		enc.addData(bytes.Repeat([]byte{byte(i + 1)}, 50))
	}
	drop := 3
	for i, p := range pkts {
		if i < drop {
			continue
		}
		dec.input(p)
	}
	if len(got) != 0 {
		t.Fatalf("unrecoverable block should deliver nothing, got %d", len(got))
	}

	// Block 1: clean → must deliver all n.
	pkts = nil
	want := make([][]byte, n)
	for i := 0; i < n; i++ {
		want[i] = bytes.Repeat([]byte{byte(100 + i)}, 33)
		enc.addData(want[i])
	}
	for _, p := range pkts {
		dec.input(p)
	}
	if len(got) != n {
		t.Fatalf("clean block delivered %d, want %d", len(got), n)
	}
	for i := 0; i < n; i++ {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("block1 frame %d mismatch", i)
		}
	}
}

// A passthrough (type-0) packet must be delivered verbatim, unaffected by FEC blocks.
func TestFecStreamPassthrough(t *testing.T) {
	var got [][]byte
	dec := newFecDecoder(func(f []byte) { got = append(got, append([]byte(nil), f...)) })
	msg := []byte("handshake-init-bytes")
	dec.input(append([]byte{fecTypePass}, msg...))
	if len(got) != 1 || !bytes.Equal(got[0], msg) {
		t.Fatalf("passthrough not delivered verbatim: %v", got)
	}
}
