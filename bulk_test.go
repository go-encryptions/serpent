package serpent

import (
	"bytes"
	"testing"
)

// A variant runs a test body with some vector kernels switched off, so that
// every path (AVX-512, AVX2, pure Go) is tested on a machine that has them
// all; the amd64 test file adds the variants.
type variant struct {
	name string
	run  func(func())
}

var variants = []variant{{"default", func(f func()) { f() }}}

func eachVariant(t *testing.T, body func(*testing.T)) {
	t.Helper()
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) { v.run(func() { body(t) }) })
	}
}

// oracle is the pure-Go single-block path: Encrypt and Decrypt one block at a
// time. It shares the S-box source (sbox.go) with the generated kernels, so
// the Botan known-answer vectors, which go through this path, are what vouch
// for the S-boxes themselves; the vector code is held to this oracle.
func oracle(c *serpentCipher, src []byte, dec bool) []byte {
	out := make([]byte, len(src))
	for o := 0; o < len(src); o += BlockSize {
		if dec {
			c.Decrypt(out[o:], src[o:])
		} else {
			c.Encrypt(out[o:], src[o:])
		}
	}
	return out
}

func testCipher(t testing.TB, keyLen int) *serpentCipher {
	t.Helper()
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = byte(i*13 + keyLen)
	}
	b, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*serpentCipher)
}

// TestBulkEveryLengthAndAlignment checks EncryptBlocks and DecryptBlocks
// against the oracle for every length from 0 to 70 blocks (all of the 4-, 8-
// and 16-block remainders, and four 16-block chunks), at source and
// destination offsets 0..40 within larger buffers (so that no kernel can rely
// on 16- or 32-byte alignment), out of place and in place. The guard bytes
// around dst must stay untouched. Assembly is invisible to go cover, so this
// is the test that holds the kernels.
func TestBulkEveryLengthAndAlignment(t *testing.T) { eachVariant(t, checkEveryLengthAndAlignment) }

func checkEveryLengthAndAlignment(t *testing.T) {
	c := testCipher(t, 32)
	const guard = 0xA5
	for n := 0; n <= 100; n++ {
		for _, so := range []int{0, 1, 7, 16, 31, 40} {
			for _, do := range []int{0, 3, 16, 32, 33} {
				plain := make([]byte, so+16*n+8)
				for i := range plain {
					plain[i] = byte(i*29 + n*3 + so)
				}
				src := plain[so : so+16*n]
				for _, dec := range []bool{false, true} {
					want := oracle(c, src, dec)
					buf := bytes.Repeat([]byte{guard}, do+16*n+do+8)
					dst := buf[do : do+16*n]
					if dec {
						c.DecryptBlocks(dst, src)
					} else {
						c.EncryptBlocks(dst, src)
					}
					if !bytes.Equal(dst, want) {
						t.Fatalf("n=%d src+%d dst+%d dec=%v: differs from the oracle", n, so, do, dec)
					}
					for i, b := range buf {
						if (i < do || i >= do+16*n) && b != guard {
							t.Fatalf("n=%d src+%d dst+%d dec=%v: wrote outside dst at %d", n, so, do, dec, i)
						}
					}
				}
			}
		}
		// In place.
		src := make([]byte, 16*n)
		for i := range src {
			src[i] = byte(i*17 + n)
		}
		for _, dec := range []bool{false, true} {
			want := oracle(c, src, dec)
			buf := append([]byte(nil), src...)
			if dec {
				c.DecryptBlocks(buf, buf)
			} else {
				c.EncryptBlocks(buf, buf)
			}
			if !bytes.Equal(buf, want) {
				t.Fatalf("n=%d in place dec=%v: differs from the oracle", n, dec)
			}
		}
	}
}

// TestBulkKeySizes runs a 70-block message under every key size, both ways,
// and checks the round trip as well as the oracle.
func TestBulkKeySizes(t *testing.T) { eachVariant(t, checkKeySizes) }

func checkKeySizes(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		c := testCipher(t, keyLen)
		src := make([]byte, 16*70)
		for i := range src {
			src[i] = byte(i*i + keyLen)
		}
		enc := make([]byte, len(src))
		c.EncryptBlocks(enc, src)
		if !bytes.Equal(enc, oracle(c, src, false)) {
			t.Fatalf("key %d: EncryptBlocks differs from the oracle", keyLen)
		}
		dec := make([]byte, len(src))
		c.DecryptBlocks(dec, enc)
		if !bytes.Equal(dec, src) {
			t.Fatalf("key %d: round trip differs", keyLen)
		}
	}
}

// A buffer larger than one call to the kernels (64 KiB on amd64) is split
// into several; 4209 blocks is more than one call's worth on every kernel
// (85 chunks of 48 blocks with AVX-512, 256 of 16 with AVX2), with a tail for
// the smaller kernels and the portable loop.
func TestBulkLargeBuffer(t *testing.T) { eachVariant(t, checkLargeBuffer) }

func checkLargeBuffer(t *testing.T) {
	c := testCipher(t, 32)
	src := make([]byte, 16*4200+16*9)
	for i := range src {
		src[i] = byte(i*131 + i>>9)
	}
	want := oracle(c, src, false)
	got := make([]byte, len(src))
	c.EncryptBlocks(got, src)
	if !bytes.Equal(got, want) {
		t.Fatal("EncryptBlocks differs on a large buffer")
	}
	c.DecryptBlocks(got, want)
	if !bytes.Equal(got, src) {
		t.Fatal("DecryptBlocks differs on a large buffer")
	}
}
