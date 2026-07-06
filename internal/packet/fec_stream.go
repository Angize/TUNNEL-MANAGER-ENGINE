// Wire layer for FEC on the datagram carriers: it turns the stream of sealed frames
// into FEC blocks (n data + k parity) on send, and reassembles+reconstructs them on
// receive. It sits between the carrier's frame layer and its socket, so both flux and
// the udp carrier can share it.
//
// When FEC is on, EVERY packet carries a 1-byte type tag so the receiver can route it:
//
//	type 0  passthrough : [0][frame]                          (ping/pong/handshake — not blocked)
//	type 1  data shard  : [1][hdr][shard]  shard = [len:2][sealed] zero-padded to shardLen
//	type 2  parity shard: [2][hdr][shard]  shard = RS parity bytes
//	hdr = [block:4][idx:1][n:1][k:1][count:1][shardLen:2]     (count = real data shards in the block)
//
// A block is flushed when it fills (n data frames) or a short timer fires; a partial
// block is zero-padded to n for the RS math but only its `count` real shards are sent
// (the receiver synthesizes the pad shards as zeros). The receiver reconstructs a block
// as soon as any n of its n+k shards arrive, then delivers the recovered sealed frames.
package packet

import (
	"encoding/binary"
	"log"
	"sync"
	"time"
)

// newFecPair builds the encoder/decoder a datagram carrier needs to run FEC, or
// (nil, nil) when fec is off or the geometry is bad (logged, so the carrier just
// runs without FEC rather than failing). emit sends one ready wire packet (the
// carrier wraps + transmits it to the peer); deliver receives each recovered frame
// (the carrier feeds it back into its normal crypto/clear path). This keeps the
// three datagram carriers (udp, raw, flux) sharing one FEC wiring.
func newFecPair(fec bool, data, parity int, name string, emit, deliver func([]byte)) (*fecEncoder, *fecDecoder) {
	if !fec {
		return nil, nil
	}
	enc, err := newFecEncoder(data, parity, emit)
	if err != nil {
		log.Printf("%s: FEC disabled (bad geometry %d+%d): %v", name, data, parity, err)
		return nil, nil
	}
	return enc, newFecDecoder(deliver)
}

// fecTag prepends the passthrough type tag to a control/handshake frame when enc is
// non-nil (FEC on), so the peer's decoder forwards it straight through instead of
// parsing it as a shard. With FEC off it returns the frame unchanged.
func fecTag(enc *fecEncoder, frame []byte) []byte {
	if enc == nil {
		return frame
	}
	return append([]byte{fecTypePass}, frame...)
}

const (
	fecTypePass   = 0
	fecTypeData   = 1
	fecTypeParity = 2
	fecHdrLen     = 1 + 4 + 1 + 1 + 1 + 1 + 2 // type + block,idx,n,k,count,shardLen
	fecFlushDelay = 15 * time.Millisecond      // flush a partial block after this idle gap
	fecKeepBlocks = 64                          // receiver: how many recent blocks to retain
)

// fecEncoder buffers sealed data frames and emits FEC block packets via emit().
type fecEncoder struct {
	codec *fecCodec
	n, k  int
	emit  func([]byte) // sends one ready wire packet (the carrier wraps + transmits it)

	mu     sync.Mutex
	block  uint32
	shards [][]byte // pending data payloads, each already [len:2][sealed]
	timer  *time.Timer
}

func newFecEncoder(n, k int, emit func([]byte)) (*fecEncoder, error) {
	c, err := newFECCodec(n, k)
	if err != nil {
		return nil, err
	}
	return &fecEncoder{codec: c, n: n, k: k, emit: emit}, nil
}

// addData queues one sealed data frame; flushes the block when it fills, else arms the timer.
func (e *fecEncoder) addData(sealed []byte) {
	sp := make([]byte, 2+len(sealed))
	binary.BigEndian.PutUint16(sp[:2], uint16(len(sealed)))
	copy(sp[2:], sealed)
	e.mu.Lock()
	e.shards = append(e.shards, sp)
	if len(e.shards) >= e.n {
		e.flushLocked()
	} else if e.timer == nil {
		e.timer = time.AfterFunc(fecFlushDelay, func() { e.mu.Lock(); e.flushLocked(); e.mu.Unlock() })
	}
	e.mu.Unlock()
}

// flushLocked encodes and emits the pending block. Caller holds e.mu.
func (e *fecEncoder) flushLocked() {
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	count := len(e.shards)
	if count == 0 {
		return
	}
	shardLen := 0
	for _, s := range e.shards {
		if len(s) > shardLen {
			shardLen = len(s)
		}
	}
	data := make([][]byte, e.n)
	for i := 0; i < e.n; i++ {
		data[i] = make([]byte, shardLen)
		if i < count {
			copy(data[i], e.shards[i])
		}
	}
	parity, err := e.codec.Encode(data)
	blk := e.block
	e.block++
	e.shards = nil
	if err != nil {
		return
	}
	hdr := func(typ byte, idx int) []byte {
		h := make([]byte, fecHdrLen)
		h[0] = typ
		binary.BigEndian.PutUint32(h[1:5], blk)
		h[5] = byte(idx)
		h[6] = byte(e.n)
		h[7] = byte(e.k)
		h[8] = byte(count)
		binary.BigEndian.PutUint16(h[9:11], uint16(shardLen))
		return h
	}
	for i := 0; i < count; i++ { // only the real data shards go on the wire
		e.emit(append(hdr(fecTypeData, i), data[i]...))
	}
	for i := 0; i < e.k; i++ {
		e.emit(append(hdr(fecTypeParity, i), parity[i]...))
	}
}

// fecBlock accumulates the shards of one block until it can be reconstructed.
type fecBlock struct {
	n, k, count, shardLen int
	shards                [][]byte // len n+k; nil = missing
	present               int
	done                  bool
}

// fecDecoder reassembles blocks and delivers recovered sealed frames via deliver().
type fecDecoder struct {
	mu      sync.Mutex
	blocks  map[uint32]*fecBlock
	maxSeen uint32
	codecs  map[int]*fecCodec // keyed by n<<8|k
	deliver func([]byte)      // called with each recovered sealed frame (in block order)
}

func newFecDecoder(deliver func([]byte)) *fecDecoder {
	return &fecDecoder{blocks: map[uint32]*fecBlock{}, codecs: map[int]*fecCodec{}, deliver: deliver}
}

func (d *fecDecoder) codec(n, k int) *fecCodec {
	key := n<<8 | k
	if c := d.codecs[key]; c != nil {
		return c
	}
	c, err := newFECCodec(n, k)
	if err != nil {
		return nil
	}
	d.codecs[key] = c
	return c
}

// input consumes one received wire packet (already stripped of the carrier header).
func (d *fecDecoder) input(pkt []byte) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] {
	case fecTypePass:
		d.deliver(pkt[1:])
		return
	case fecTypeData, fecTypeParity:
	default:
		return
	}
	if len(pkt) < fecHdrLen {
		return
	}
	typ := pkt[0]
	blk := binary.BigEndian.Uint32(pkt[1:5])
	idx := int(pkt[5])
	n, k, count := int(pkt[6]), int(pkt[7]), int(pkt[8])
	shardLen := int(binary.BigEndian.Uint16(pkt[9:11]))
	shard := pkt[fecHdrLen:]
	if n < 1 || k < 1 || n+k > 256 || count < 1 || count > n || shardLen < 2 || len(shard) != shardLen {
		return
	}
	slot := idx
	if typ == fecTypeParity {
		slot = n + idx
	}
	if slot < 0 || slot >= n+k {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.evictLocked(blk)
	b := d.blocks[blk]
	if b == nil {
		b = &fecBlock{n: n, k: k, count: count, shardLen: shardLen, shards: make([][]byte, n+k)}
		// pad shards [count, n) are known-zero and count as present for the RS math.
		for i := count; i < n; i++ {
			b.shards[i] = make([]byte, shardLen)
			b.present++
		}
		d.blocks[blk] = b
	}
	if b.done || b.shards[slot] != nil {
		return
	}
	b.shards[slot] = append([]byte(nil), shard...)
	b.present++
	if b.present < n {
		return
	}
	c := d.codec(n, k)
	if c == nil {
		return
	}
	data, err := c.Reconstruct(b.shards)
	if err != nil {
		return
	}
	b.done = true
	for i := 0; i < count; i++ { // unwrap each recovered data shard: [len:2][sealed]
		s := data[i]
		if len(s) < 2 {
			continue
		}
		ln := int(binary.BigEndian.Uint16(s[:2]))
		if 2+ln <= len(s) {
			d.deliver(append([]byte(nil), s[2:2+ln]...))
		}
	}
}

// evictLocked drops blocks far behind the newest one so the map cannot grow unbounded
// (a permanently-incomplete block is eventually forgotten). Caller holds d.mu.
func (d *fecDecoder) evictLocked(blk uint32) {
	if blk > d.maxSeen {
		d.maxSeen = blk
	}
	if len(d.blocks) <= fecKeepBlocks {
		return
	}
	for id := range d.blocks {
		if d.maxSeen-id >= fecKeepBlocks {
			delete(d.blocks, id)
		}
	}
}
