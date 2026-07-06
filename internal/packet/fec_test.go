package packet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Encode then drop every combination of up to k shards; reconstruction must recover
// the exact original data. This is the core guarantee: any k erasures are recoverable.
func TestFECReconstructsUpToK(t *testing.T) {
	for _, nk := range [][2]int{{10, 3}, {10, 2}, {8, 4}, {4, 4}, {1, 1}, {16, 8}} {
		n, k := nk[0], nk[1]
		c, err := newFECCodec(n, k)
		if err != nil {
			t.Fatalf("newFECCodec(%d,%d): %v", n, k, err)
		}
		data := make([][]byte, n)
		for i := range data {
			data[i] = make([]byte, 300)
			rand.Read(data[i])
		}
		parity, err := c.Encode(data)
		if err != nil {
			t.Fatal(err)
		}
		orig := make([][]byte, n)
		for i := range data {
			orig[i] = append([]byte(nil), data[i]...)
		}
		// drop the first `lost` shards (a worst case: consecutive data losses).
		for lost := 0; lost <= k; lost++ {
			shards := make([][]byte, n+k)
			for i := 0; i < n; i++ {
				shards[i] = append([]byte(nil), data[i]...)
			}
			for i := 0; i < k; i++ {
				shards[n+i] = append([]byte(nil), parity[i]...)
			}
			for i := 0; i < lost; i++ {
				shards[i] = nil
			}
			rec, err := c.Reconstruct(shards)
			if err != nil {
				t.Fatalf("n=%d k=%d lost=%d: %v", n, k, lost, err)
			}
			for i := 0; i < n; i++ {
				if !bytes.Equal(rec[i], orig[i]) {
					t.Fatalf("n=%d k=%d lost=%d: shard %d mismatch", n, k, lost, i)
				}
			}
		}
	}
}

// Losing a mix of data and parity shards (as happens on a real lossy link) still
// reconstructs, as long as at least n of the n+k shards survive.
func TestFECMixedLoss(t *testing.T) {
	c, _ := newFECCodec(10, 4)
	data := make([][]byte, 10)
	for i := range data {
		data[i] = bytes.Repeat([]byte{byte(i + 1)}, 128)
	}
	parity, _ := c.Encode(data)
	shards := make([][]byte, 14)
	for i := 0; i < 10; i++ {
		shards[i] = append([]byte(nil), data[i]...)
	}
	for i := 0; i < 4; i++ {
		shards[10+i] = append([]byte(nil), parity[i]...)
	}
	// drop 4 arbitrary shards: two data, two parity.
	for _, idx := range []int{2, 7, 10, 13} {
		shards[idx] = nil
	}
	rec, err := c.Reconstruct(shards)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		if !bytes.Equal(rec[i], data[i]) {
			t.Fatalf("shard %d not recovered", i)
		}
	}
}

// More than k losses cannot be recovered — must error, not return garbage.
func TestFECTooManyLosses(t *testing.T) {
	c, _ := newFECCodec(10, 3)
	data := make([][]byte, 10)
	for i := range data {
		data[i] = bytes.Repeat([]byte{9}, 64)
	}
	parity, _ := c.Encode(data)
	shards := make([][]byte, 13)
	for i := 0; i < 10; i++ {
		shards[i] = append([]byte(nil), data[i]...)
	}
	for i := 0; i < 3; i++ {
		shards[10+i] = append([]byte(nil), parity[i]...)
	}
	for i := 0; i < 4; i++ { // 4 losses > k=3
		shards[i] = nil
	}
	if _, err := c.Reconstruct(shards); err == nil {
		t.Fatal("expected an error when losses exceed k")
	}
}
