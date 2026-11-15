//go:build amd64 && !purego

package serpent

import (
	"bytes"
	"testing"
	"unsafe"
)

// realAVX2 and realAVX512 are what the processor reports. Where it lacks a
// feature, the gate is forced on and the kernels are Go stand-ins, so that the
// dispatch in bulkBlocks (plain Go) runs, and is covered, on every machine;
// only the one-line kernel calls need the hardware, and the TestKernels* tests
// skip without it.
var realAVX2, realAVX512 = useAVX2, useAVX512

// standIn is a kernel in Go: n chunks of blocks blocks, one block at a time.
func standIn(dec bool, blocks int) kernFn {
	return func(rk *uint32, dst, src *byte, n int) {
		c := &serpentCipher{rk: *(*[4 * (rounds + 1)]uint32)(unsafe.Pointer(rk))}
		total := n * blocks * BlockSize
		d, s := unsafe.Slice(dst, total), unsafe.Slice(src, total)
		for o := 0; o < total; o += BlockSize {
			if dec {
				c.Decrypt(d[o:], s[o:])
			} else {
				c.Encrypt(d[o:], s[o:])
			}
		}
	}
}

func init() {
	pair := func(blocks int) kernPair { return kernPair{standIn(false, blocks), standIn(true, blocks)} }
	if !realAVX2 {
		kern.avx2x8, kern.avx2x16, useAVX2 = pair(8), pair(16), true
	}
	if !realAVX512 {
		kern.avx512x16, kern.avx512x32, kern.avx512x48, useAVX512 = pair(16), pair(32), pair(48), true
	}
}

// withGates runs f with the vector kernels on or off, restoring the gates.
func withGates(avx512, avx2 bool, f func()) {
	s512, s2 := useAVX512, useAVX2
	useAVX512, useAVX2 = avx512 && s512, avx2 && s2
	defer func() { useAVX512, useAVX2 = s512, s2 }()
	f()
}

// The variants of bulk_test.go: AVX-512 off (AVX2 only), AVX2 off (AVX-512
// only, the CPU that has the one and not the other, or the tail of a buffer
// that the 16-block AVX-512 chunks leave to pure Go) and both off (pure Go),
// on top of the default (everything the CPU has).
func init() {
	variants = append(variants,
		variant{"avx2-only", func(f func()) { withGates(false, true, f) }},
		variant{"avx512-only", func(f func()) { withGates(true, false, f) }},
		variant{"pure-go", func(f func()) { withGates(false, false, f) }},
	)
}

func skipWithoutAVX2(t *testing.T) {
	t.Helper()
	if !hasAVX2() {
		t.Skip("no AVX2 on this CPU")
	}
}

func skipWithoutAVX512(t *testing.T) {
	t.Helper()
	if !hasAVX512F() {
		t.Skip("no AVX-512F on this CPU")
	}
}

// With every gate off, bulkBlocks does nothing and the pure-Go four-block
// loops take every length: the path of a CPU (or an OS) without AVX2.
func TestBulkGatesOffFallBack(t *testing.T) {
	c := testCipher(t, 16)
	withGates(false, false, func() {
		for n := 0; n <= 40; n++ {
			src := make([]byte, 16*n)
			for i := range src {
				src[i] = byte(i*5 + n)
			}
			if got := c.bulkBlocks(make([]byte, len(src)), src, false); got != 0 {
				t.Fatalf("gates off: bulkBlocks did %d bytes", got)
			}
			enc := make([]byte, len(src))
			c.EncryptBlocks(enc, src)
			if !bytes.Equal(enc, oracle(c, src, false)) {
				t.Fatalf("gates off, n=%d: EncryptBlocks differs", n)
			}
			dec := make([]byte, len(src))
			c.DecryptBlocks(dec, enc)
			if !bytes.Equal(dec, src) {
				t.Fatalf("gates off, n=%d: DecryptBlocks differs", n)
			}
		}
	})
}

// bulkBlocks must report exactly the bytes it did. With AVX2 only: 16-block
// chunks, then one 8-block chunk.
func TestBulkReportsWhatItDidAVX2(t *testing.T) {
	c := testCipher(t, 24)
	withGates(false, true, func() {
		for n, want := range map[int]int{0: 0, 7: 0, 8: 8, 15: 8, 16: 16, 23: 16, 24: 24, 33: 32, 40: 40, 47: 40} {
			src := make([]byte, 16*n)
			for _, dec := range []bool{false, true} {
				if got := c.bulkBlocks(make([]byte, len(src)), src, dec); got != 16*want {
					t.Errorf("%d blocks dec=%v: did %d bytes, want %d", n, dec, got, 16*want)
				}
			}
		}
	})
}

// With AVX-512 (and AVX2 below it): 48-, 32- and 16-block chunks, then the
// AVX2 kernels take what is left of 8 or more blocks.
func TestBulkReportsWhatItDidAVX512(t *testing.T) {
	c := testCipher(t, 24)
	withGates(true, true, func() {
		for n, want := range map[int]int{
			0: 0, 7: 0, 8: 8 * boolInt(useAVX2), 15: 8 * boolInt(useAVX2),
			16: 16, 31: 16 + 8*boolInt(useAVX2), 32: 32, 47: 32 + 8*boolInt(useAVX2),
			48: 48, 63: 48 + 8*boolInt(useAVX2), 64: 64, 96: 96,
		} {
			src := make([]byte, 16*n)
			for _, dec := range []bool{false, true} {
				if got := c.bulkBlocks(make([]byte, len(src)), src, dec); got != 16*want {
					t.Errorf("%d blocks dec=%v: did %d bytes, want %d", n, dec, got, 16*want)
				}
			}
		}
	})
}

// With AVX-512 and no AVX2: 48-, 32- and 16-block chunks, and what is left of
// fewer than 16 blocks is not touched, since no AVX2 kernel takes it.
func TestBulkReportsWhatItDidAVX512Only(t *testing.T) {
	c := testCipher(t, 24)
	withGates(true, false, func() {
		for n, want := range map[int]int{
			0: 0, 7: 0, 8: 0, 15: 0, 16: 16, 31: 16, 32: 32, 47: 32, 48: 48, 63: 48, 64: 64, 96: 96,
		} {
			src := make([]byte, 16*n)
			for _, dec := range []bool{false, true} {
				if got := c.bulkBlocks(make([]byte, len(src)), src, dec); got != 16*want {
					t.Errorf("%d blocks dec=%v: did %d bytes, want %d", n, dec, got, 16*want)
				}
			}
		}
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Each kernel on its own, over several chunks, against the oracle, so that
// the dispatcher is free to pick any of them.
func TestKernelsAgree(t *testing.T) {
	skipWithoutAVX2(t)
	c := testCipher(t, 32)
	src := make([]byte, 16*96)
	for i := range src {
		src[i] = byte(i*11 + i>>8)
	}
	type kern func(rk *uint32, dst, src *byte, n int)
	run := func(name string, k kern, chunks int, want []byte) {
		t.Helper()
		got := make([]byte, len(src))
		k(&c.rk[0], &got[0], &src[0], chunks)
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the oracle", name)
		}
		var none [256]byte
		k(&c.rk[0], &none[0], &src[0], 0) // n = 0 must do nothing
		if none != [256]byte{} {
			t.Errorf("%s: n=0 wrote output", name)
		}
	}
	for _, dec := range []bool{false, true} {
		want := oracle(c, src, dec)
		if dec {
			run("dec avx2 x8", decryptBlocksAVX2x8, 12, want)
			run("dec avx2 x16", decryptBlocksAVX2x16, 6, want)
		} else {
			run("enc avx2 x8", encryptBlocksAVX2x8, 12, want)
			run("enc avx2 x16", encryptBlocksAVX2x16, 6, want)
		}
		if !hasAVX512F() {
			continue
		}
		if dec {
			run("dec avx512 x16", decryptBlocksAVX512x16, 6, want)
			run("dec avx512 x32", decryptBlocksAVX512x32, 3, want)
			run("dec avx512 x48", decryptBlocksAVX512x48, 2, want)
		} else {
			run("enc avx512 x16", encryptBlocksAVX512x16, 6, want)
			run("enc avx512 x32", encryptBlocksAVX512x32, 3, want)
			run("enc avx512 x48", encryptBlocksAVX512x48, 2, want)
		}
	}
}

func TestHasFeaturesStable(t *testing.T) {
	first2, first512 := hasAVX2(), hasAVX512F()
	for range 50 {
		if hasAVX2() != first2 || hasAVX512F() != first512 {
			t.Fatal("a feature probe changed its answer")
		}
	}
	if realAVX2 != first2 || realAVX512 != first512 {
		t.Fatalf("gates (%v, %v) differ from probes (%v, %v)", realAVX2, realAVX512, first2, first512)
	}
}

// BenchmarkKernels runs every kernel over the same 4 KiB-ish buffer.
func BenchmarkKernels(b *testing.B) {
	c := testCipher(b, 32)
	src := make([]byte, 6144)
	dst := make([]byte, 6144)
	type kern func(rk *uint32, dst, src *byte, n int)
	for _, k := range []struct {
		name  string
		f     kern
		bytes int
		need  func() bool
	}{
		{"avx2-x8", encryptBlocksAVX2x8, 128, hasAVX2},
		{"avx2-x16", encryptBlocksAVX2x16, 256, hasAVX2},
		{"avx512-x16", encryptBlocksAVX512x16, 256, hasAVX512F},
		{"avx512-x32", encryptBlocksAVX512x32, 512, hasAVX512F},
		{"avx512-x48", encryptBlocksAVX512x48, 768, hasAVX512F},
	} {
		b.Run(k.name, func(b *testing.B) {
			if !k.need() {
				b.Skip("feature missing")
			}
			chunks := 4096 / k.bytes
			if chunks == 0 {
				chunks = 1
			}
			b.SetBytes(int64(chunks * k.bytes))
			for range b.N {
				k.f(&c.rk[0], &dst[0], &src[0], chunks)
			}
		})
	}
}
