// Forward error correction for the datagram carriers (udp / stun / raw / flux): a
// systematic Reed-Solomon ERASURE code over GF(256). For every block of n data
// shards we emit k parity shards; the receiver, which knows exactly which shards
// are missing (gaps in the per-shard index), can reconstruct up to k lost shards
// of the block WITHOUT a retransmit. This is what keeps a throttled/high-loss
// link (the Iran scenario) usable: losses are repaired locally instead of
// collapsing the inner TCP with retransmits and congestion backoff.
//
// This file is the pure codec (platform-independent, unit-tested). The wire
// framing + block buffering that carries it live in the transport.
package packet

import "errors"

// GF(256) arithmetic with the standard AES/RS primitive polynomial 0x11d.
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ { // duplicate so gfExp[a+b] never needs a mod
		gfExp[i] = gfExp[i-255]
	}
}

func gmul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gdiv(a, b byte) byte { // b != 0
	if a == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])-int(gfLog[b])+255]
}

// fecCodec is a systematic Reed-Solomon codec for (n data, k parity) shards. The
// parity rows come from a Cauchy matrix, so ANY n of the n+k rows form an
// invertible matrix — i.e. any k erasures are recoverable.
type fecCodec struct {
	n, k   int
	parity [][]byte // k rows × n cols: parity[i][j] = coefficient of data j in parity i
}

// newFECCodec builds a codec for n data + k parity shards. n>=1, k>=1, n+k<=256.
func newFECCodec(n, k int) (*fecCodec, error) {
	if n < 1 || k < 1 || n+k > 256 {
		return nil, errors.New("fec: bad (n,k)")
	}
	// Cauchy matrix: rows x_i = n+i (i<k), cols y_j = j (j<n); all distinct, so
	// C[i][j] = 1/(x_i XOR y_j) and every square submatrix is invertible.
	p := make([][]byte, k)
	for i := 0; i < k; i++ {
		p[i] = make([]byte, n)
		xi := byte(n + i)
		for j := 0; j < n; j++ {
			p[i][j] = gdiv(1, xi^byte(j))
		}
	}
	return &fecCodec{n: n, k: k, parity: p}, nil
}

// Encode returns the k parity shards for the n equal-length data shards.
func (c *fecCodec) Encode(data [][]byte) ([][]byte, error) {
	if len(data) != c.n {
		return nil, errors.New("fec: need exactly n data shards")
	}
	sz := len(data[0])
	for _, d := range data {
		if len(d) != sz {
			return nil, errors.New("fec: data shards must be equal length")
		}
	}
	out := make([][]byte, c.k)
	for i := 0; i < c.k; i++ {
		row := make([]byte, sz)
		for j := 0; j < c.n; j++ {
			coef := c.parity[i][j]
			if coef == 0 {
				continue
			}
			dj := data[j]
			for b := 0; b < sz; b++ {
				row[b] ^= gmul(coef, dj[b])
			}
		}
		out[i] = row
	}
	return out, nil
}

// Reconstruct recovers the n data shards from any n present shards. shards is
// indexed 0..n+k-1 (0..n-1 data, n..n+k-1 parity); a missing shard is nil. All
// present shards must share one length. Returns the n data shards (freshly filled
// for the ones that were missing), or an error if fewer than n shards are present.
func (c *fecCodec) Reconstruct(shards [][]byte) ([][]byte, error) {
	if len(shards) != c.n+c.k {
		return nil, errors.New("fec: shards must be length n+k")
	}
	// Fast path: all data shards present.
	haveAllData := true
	sz := 0
	for i := 0; i < c.n+c.k; i++ {
		if shards[i] != nil {
			// All present shards must share one length; bail rather than read past a
			// shorter shard in the XOR loops below (defence in depth against a decoder
			// that ever admits mixed-length shards for one block).
			if sz != 0 && len(shards[i]) != sz {
				return nil, errors.New("fec: mixed shard lengths")
			}
			sz = len(shards[i])
		}
		if i < c.n && shards[i] == nil {
			haveAllData = false
		}
	}
	if haveAllData {
		return shards[:c.n], nil
	}
	// Collect the first n present shards and the rows of the full encode matrix
	// (identity for data, Cauchy for parity) that produced them.
	rows := make([][]byte, 0, c.n) // n×n matrix (each present shard's encode row)
	vals := make([][]byte, 0, c.n) // the present shard bytes, same order
	for i := 0; i < c.n+c.k && len(rows) < c.n; i++ {
		if shards[i] == nil {
			continue
		}
		row := make([]byte, c.n)
		if i < c.n {
			row[i] = 1 // identity row for a data shard
		} else {
			copy(row, c.parity[i-c.n]) // Cauchy row for a parity shard
		}
		rows = append(rows, row)
		vals = append(vals, shards[i])
	}
	if len(rows) < c.n {
		return nil, errors.New("fec: not enough shards to reconstruct")
	}
	inv, err := gfInvert(rows)
	if err != nil {
		return nil, err
	}
	// data = inv * vals  (matrix × shard-vector over GF(256), byte-wise)
	data := make([][]byte, c.n)
	for r := 0; r < c.n; r++ {
		if shards[r] != nil {
			data[r] = shards[r] // keep the original data shard untouched
			continue
		}
		out := make([]byte, sz)
		for cc := 0; cc < c.n; cc++ {
			coef := inv[r][cc]
			if coef == 0 {
				continue
			}
			v := vals[cc]
			for b := 0; b < sz; b++ {
				out[b] ^= gmul(coef, v[b])
			}
		}
		data[r] = out
	}
	return data, nil
}

// gfInvert inverts an n×n GF(256) matrix via Gauss-Jordan elimination.
func gfInvert(m [][]byte) ([][]byte, error) {
	n := len(m)
	a := make([][]byte, n) // working copy augmented with the identity
	for i := range m {
		a[i] = make([]byte, 2*n)
		copy(a[i], m[i])
		a[i][n+i] = 1
	}
	for col := 0; col < n; col++ {
		// pivot
		if a[col][col] == 0 {
			sw := -1
			for r := col + 1; r < n; r++ {
				if a[r][col] != 0 {
					sw = r
					break
				}
			}
			if sw < 0 {
				return nil, errors.New("fec: singular matrix")
			}
			a[col], a[sw] = a[sw], a[col]
		}
		// normalize pivot row
		pv := a[col][col]
		for x := 0; x < 2*n; x++ {
			a[col][x] = gdiv(a[col][x], pv)
		}
		// eliminate other rows
		for r := 0; r < n; r++ {
			if r == col || a[r][col] == 0 {
				continue
			}
			f := a[r][col]
			for x := 0; x < 2*n; x++ {
				a[r][x] ^= gmul(f, a[col][x])
			}
		}
	}
	inv := make([][]byte, n)
	for i := 0; i < n; i++ {
		inv[i] = a[i][n:]
	}
	return inv, nil
}
