package serpent

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

type vector struct{ key, in, out []byte }

// readVectors parses Botan's "Key = / In = / Out =" format. In and Out hold
// one or more consecutive 16-byte blocks, each enciphered independently (ECB).
func readVectors(t testing.TB, path string) []vector {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var vs []vector
	var cur vector
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		name, val, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		b, err := hex.DecodeString(val)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		switch name {
		case "Key":
			cur = vector{key: b}
		case "In":
			cur.in = b
		case "Out":
			cur.out = b
			vs = append(vs, cur)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return vs
}

func checkVectors(t *testing.T, path string, wantMin int) {
	vs := readVectors(t, path)
	if len(vs) < wantMin {
		t.Fatalf("%s: only %d vectors parsed, want at least %d", path, len(vs), wantMin)
	}
	sizes := map[int]int{}
	for _, v := range vs {
		sizes[len(v.key)]++
		c, err := NewCipher(v.key)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.in)%16 != 0 || len(v.in) != len(v.out) {
			t.Fatalf("bad vector lengths %d/%d", len(v.in), len(v.out))
		}
		got := make([]byte, len(v.in))
		for i := 0; i < len(v.in); i += 16 {
			c.Encrypt(got[i:], v.in[i:])
		}
		if !bytes.Equal(got, v.out) {
			t.Fatalf("key %x: encrypt = %x, want %x", v.key, got, v.out)
		}
		for i := 0; i < len(v.in); i += 16 {
			c.Decrypt(got[i:], v.out[i:])
		}
		if !bytes.Equal(got, v.in) {
			t.Fatalf("key %x: decrypt = %x, want %x", v.key, got, v.in)
		}
	}
	t.Logf("%s: %d vectors, by key length %v", path, len(vs), sizes)
}

// Botan's src/tests/data/block/serpent.vec: standard (non-reversed) order.
func TestBotanVectors(t *testing.T) {
	checkVectors(t, "testdata/botan-serpent.vec", 1000)
}

// Differential corpus produced by internal/genbotan from the installed
// `botan cipher` (Serpent/CBC/NoPadding with a zero IV on one block).
func TestBotanDifferential(t *testing.T) {
	checkVectors(t, "testdata/botan-diff.vec", 600)
}

func TestKeySize(t *testing.T) {
	for n := 0; n <= 40; n++ {
		c, err := NewCipher(make([]byte, n))
		if n == 16 || n == 24 || n == 32 {
			if err != nil || c.BlockSize() != 16 {
				t.Fatalf("key %d: %v", n, err)
			}
			continue
		}
		var kse KeySizeError
		if c != nil || !errors.As(err, &kse) || int(kse) != n {
			t.Fatalf("key %d: got %v, %v", n, c, err)
		}
		if !strings.Contains(err.Error(), "invalid key size") {
			t.Fatal(err)
		}
	}
}

func TestPanics(t *testing.T) {
	c, _ := NewCipher(make([]byte, 16))
	for name, f := range map[string]func(){
		"enc short src": func() { c.Encrypt(make([]byte, 16), make([]byte, 15)) },
		"enc short dst": func() { c.Encrypt(make([]byte, 15), make([]byte, 16)) },
		"dec short src": func() { c.Decrypt(make([]byte, 16), make([]byte, 15)) },
		"dec short dst": func() { c.Decrypt(make([]byte, 15), make([]byte, 16)) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

func TestInPlace(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c, _ := NewCipher(key)
	pt := []byte("sixteen byte blk")
	want := make([]byte, 16)
	c.Encrypt(want, pt)
	buf := append([]byte(nil), pt...)
	c.Encrypt(buf, buf)
	if !bytes.Equal(buf, want) {
		t.Fatal("in-place encrypt differs")
	}
	c.Decrypt(buf, buf)
	if !bytes.Equal(buf, pt) {
		t.Fatal("in-place decrypt differs")
	}
}

type blocksCipher interface {
	cipher.Block
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

// EncryptBlocks and DecryptBlocks must equal block-by-block Encrypt and
// Decrypt for every length around the 4-block batch, for every key size, out
// of place and in place.
func TestBlocks(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		key := make([]byte, keyLen)
		for i := range key {
			key[i] = byte(i*7 + keyLen)
		}
		b, _ := NewCipher(key)
		c, ok := b.(blocksCipher)
		if !ok {
			t.Fatal("no EncryptBlocks/DecryptBlocks")
		}
		for n := 0; n <= 11; n++ {
			src := make([]byte, 16*n)
			for i := range src {
				src[i] = byte(i*31 + n)
			}
			want := make([]byte, len(src))
			for o := 0; o < len(src); o += 16 {
				c.Encrypt(want[o:], src[o:])
			}
			got := make([]byte, len(src))
			c.EncryptBlocks(got, src)
			if !bytes.Equal(got, want) {
				t.Fatalf("key %d, %d blocks: EncryptBlocks differs", keyLen, n)
			}
			c.DecryptBlocks(got, want)
			if !bytes.Equal(got, src) {
				t.Fatalf("key %d, %d blocks: DecryptBlocks differs", keyLen, n)
			}
			buf := append([]byte(nil), src...)
			c.EncryptBlocks(buf, buf)
			if !bytes.Equal(buf, want) {
				t.Fatalf("key %d, %d blocks: in-place EncryptBlocks differs", keyLen, n)
			}
			c.DecryptBlocks(buf, buf)
			if !bytes.Equal(buf, src) {
				t.Fatalf("key %d, %d blocks: in-place DecryptBlocks differs", keyLen, n)
			}
		}
	}
}

// The batch path must also agree with Botan's vectors: every vector's blocks
// are run through EncryptBlocks as one call.
func TestBlocksVectors(t *testing.T) {
	for _, path := range []string{"testdata/botan-serpent.vec", "testdata/botan-diff.vec"} {
		for _, v := range readVectors(t, path) {
			b, err := NewCipher(v.key)
			if err != nil {
				t.Fatal(err)
			}
			c := b.(blocksCipher)
			got := make([]byte, len(v.in))
			c.EncryptBlocks(got, v.in)
			if !bytes.Equal(got, v.out) {
				t.Fatalf("%s: EncryptBlocks differs from vector", path)
			}
			c.DecryptBlocks(got, v.out)
			if !bytes.Equal(got, v.in) {
				t.Fatalf("%s: DecryptBlocks differs from vector", path)
			}
		}
	}
}

func TestBlocksPanics(t *testing.T) {
	b, _ := NewCipher(make([]byte, 16))
	c := b.(blocksCipher)
	for name, f := range map[string]func(){
		"enc partial block": func() { c.EncryptBlocks(make([]byte, 32), make([]byte, 17)) },
		"enc short dst":     func() { c.EncryptBlocks(make([]byte, 16), make([]byte, 32)) },
		"dec partial block": func() { c.DecryptBlocks(make([]byte, 32), make([]byte, 17)) },
		"dec short dst":     func() { c.DecryptBlocks(make([]byte, 16), make([]byte, 32)) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

func roundTrip(t testing.TB, c cipher.Block, p []byte) {
	ct := make([]byte, 16)
	c.Encrypt(ct, p)
	back := make([]byte, 16)
	c.Decrypt(back, ct)
	if !bytes.Equal(back, p) {
		t.Fatalf("round trip failed: %x -> %x -> %x", p, ct, back)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(make([]byte, 16), make([]byte, 16))
	f.Add(make([]byte, 24), []byte("0123456789abcdef"))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0xa5}, 16))
	// 11 blocks: two 4-block batches and a 3-block tail, so a plain `go test`
	// reaches the batched lanes.
	long := make([]byte, 176)
	for i := range long {
		long[i] = byte(i*13 + 5)
	}
	f.Add(bytes.Repeat([]byte{0x3c}, 32), long)
	f.Fuzz(func(t *testing.T, key, block []byte) {
		c, err := NewCipher(key)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			if err == nil {
				t.Fatal("bad key accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		// The batched path against block-by-block, on 0..11 fuzzed blocks.
		n := min(len(block)/16, 11)
		src := block[:16*n]
		want := make([]byte, len(src))
		for o := 0; o < len(src); o += 16 {
			c.Encrypt(want[o:], src[o:])
		}
		bc := c.(blocksCipher)
		got := make([]byte, len(src))
		bc.EncryptBlocks(got, src)
		if !bytes.Equal(got, want) {
			t.Fatalf("EncryptBlocks differs on %d blocks", n)
		}
		bc.DecryptBlocks(got, want)
		if !bytes.Equal(got, src) {
			t.Fatalf("DecryptBlocks differs on %d blocks", n)
		}
		if len(block) < 16 {
			return
		}
		roundTrip(t, c, block[:16])
		// Encrypt must be a function of the block alone.
		a, b := make([]byte, 16), make([]byte, 16)
		c.Encrypt(a, block[:16])
		c.Encrypt(b, block[:16])
		if !bytes.Equal(a, b) {
			t.Fatal("encrypt not deterministic")
		}
	})
}

func benchBlock(b *testing.B, dec bool) {
	c, _ := NewCipher(bytes.Repeat([]byte{7}, 32))
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for o := 0; o < len(buf); o += 16 {
			if dec {
				c.Decrypt(buf[o:o+16], buf[o:o+16])
			} else {
				c.Encrypt(buf[o:o+16], buf[o:o+16])
			}
		}
	}
}

// benchBlocks is the shape of `botan speed`: one 4 KiB buffer (an XTS sector),
// 256 blocks per call, ECB-style.
func benchBlocks(b *testing.B, dec bool) {
	c, _ := NewCipher(bytes.Repeat([]byte{7}, 32))
	bc := c.(blocksCipher)
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if dec {
			bc.DecryptBlocks(buf, buf)
		} else {
			bc.EncryptBlocks(buf, buf)
		}
	}
}

func BenchmarkEncrypt(b *testing.B)       { benchBlock(b, false) }
func BenchmarkDecrypt(b *testing.B)       { benchBlock(b, true) }
func BenchmarkEncryptBlocks(b *testing.B) { benchBlocks(b, false) }
func BenchmarkDecryptBlocks(b *testing.B) { benchBlocks(b, true) }
