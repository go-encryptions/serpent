//go:build amd64 && !purego

package serpent

import (
	"bytes"
	"testing"
)

// withAVX2 runs f with the vector kernels on or off, restoring the gate.
func withAVX2(on bool, f func()) {
	saved := useAVX2
	useAVX2 = on
	defer func() { useAVX2 = saved }()
	f()
}

func skipWithoutAVX2(t *testing.T) {
	t.Helper()
	if !hasAVX2() {
		t.Skip("no AVX2 on this CPU")
	}
}

// With the gate off, the pure-Go four-block loops must give the oracle's
// answer for every length: this is the path of a CPU (or an OS) without AVX2.
func TestBulkGateOffFallsBack(t *testing.T) {
	c := testCipher(t, 16)
	withAVX2(false, func() {
		for n := 0; n <= 40; n++ {
			src := make([]byte, 16*n)
			for i := range src {
				src[i] = byte(i*5 + n)
			}
			if got := c.bulkBlocks(make([]byte, len(src)), src, false); got != 0 {
				t.Fatalf("gate off: bulkBlocks did %d bytes", got)
			}
			enc := make([]byte, len(src))
			c.EncryptBlocks(enc, src)
			if !bytes.Equal(enc, oracle(c, src, false)) {
				t.Fatalf("gate off, n=%d: EncryptBlocks differs", n)
			}
			dec := make([]byte, len(src))
			c.DecryptBlocks(dec, enc)
			if !bytes.Equal(dec, src) {
				t.Fatalf("gate off, n=%d: DecryptBlocks differs", n)
			}
		}
	})
}

// bulkBlocks must report exactly the bytes it did: 16 blocks per x16 chunk,
// then one x8 chunk if 8 or more blocks remain.
func TestBulkReportsWhatItDid(t *testing.T) {
	skipWithoutAVX2(t)
	c := testCipher(t, 24)
	for n, want := range map[int]int{0: 0, 7: 0, 8: 8, 15: 8, 16: 16, 23: 16, 24: 24, 33: 32, 40: 40, 47: 40} {
		src := make([]byte, 16*n)
		for _, dec := range []bool{false, true} {
			if got := c.bulkBlocks(make([]byte, len(src)), src, dec); got != 16*want {
				t.Errorf("%d blocks dec=%v: did %d bytes, want %d", n, dec, got, 16*want)
			}
		}
	}
}

// Each kernel on its own, over several chunks, against the oracle: the x8 and
// the x16 forms must agree with each other and with the one-block path, so
// that the dispatcher is free to pick either.
func TestKernelsAgree(t *testing.T) {
	skipWithoutAVX2(t)
	c := testCipher(t, 32)
	src := make([]byte, 16*48)
	for i := range src {
		src[i] = byte(i*11 + i>>8)
	}
	for _, dec := range []bool{false, true} {
		want := oracle(c, src, dec)
		x8 := make([]byte, len(src))
		x16 := make([]byte, len(src))
		if dec {
			decryptBlocksAVX2x8(&c.rk[0], &x8[0], &src[0], 6)
			decryptBlocksAVX2x16(&c.rk[0], &x16[0], &src[0], 3)
		} else {
			encryptBlocksAVX2x8(&c.rk[0], &x8[0], &src[0], 6)
			encryptBlocksAVX2x16(&c.rk[0], &x16[0], &src[0], 3)
		}
		if !bytes.Equal(x8, want) {
			t.Errorf("dec=%v: x8 kernel differs from the oracle", dec)
		}
		if !bytes.Equal(x16, want) {
			t.Errorf("dec=%v: x16 kernel differs from the oracle", dec)
		}
	}
	// n = 0 must do nothing, not loop 2^64 times.
	var dst [128]byte
	encryptBlocksAVX2x8(&c.rk[0], &dst[0], &src[0], 0)
	decryptBlocksAVX2x16(&c.rk[0], &dst[0], &src[0], 0)
	if dst != [128]byte{} {
		t.Error("n=0 wrote output")
	}
}

// The kernels use only Y registers and end in VZEROUPPER; this checks that
// a Go function using SSE state around a call is not disturbed (the classic
// AVX-SSE transition bug would show as a slowdown, not a wrong answer, so
// what is asserted here is the answer).
func TestHasAVX2Stable(t *testing.T) {
	first := hasAVX2()
	for range 50 {
		if hasAVX2() != first {
			t.Fatal("hasAVX2 changed its answer")
		}
	}
	if useAVX2 != first {
		t.Fatalf("useAVX2 = %v, hasAVX2() = %v", useAVX2, first)
	}
}

// BenchmarkKernels runs the x8 and the x16 kernel over the same 4 KiB, to show
// what interleaving two groups buys.
func BenchmarkKernels(b *testing.B) {
	if !hasAVX2() {
		b.Skip("no AVX2")
	}
	c := testCipher(b, 32)
	src := make([]byte, 4096)
	dst := make([]byte, 4096)
	b.Run("x8", func(b *testing.B) {
		b.SetBytes(4096)
		for range b.N {
			encryptBlocksAVX2x8(&c.rk[0], &dst[0], &src[0], 4096/128)
		}
	})
	b.Run("x16", func(b *testing.B) {
		b.SetBytes(4096)
		for range b.N {
			encryptBlocksAVX2x16(&c.rk[0], &dst[0], &src[0], 4096/256)
		}
	})
}
