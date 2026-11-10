<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/serpent" width="720"></p>

# go-encryptions/serpent

[![ci](https://github.com/go-encryptions/serpent/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/serpent/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-encryptions/serpent.svg)](https://pkg.go.dev/github.com/go-encryptions/serpent)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go **Serpent** block cipher (Anderson, Biham and Knudsen, AES finalist) as a standard `crypto/cipher.Block`: 16-byte blocks, 16-, 24- or 32-byte keys. Bitsliced, no cgo, no dependency outside the standard library.

Its first consumer is [`go-fde/veracrypt`](https://github.com/go-fde/veracrypt), which needs Serpent in XTS mode with 256-bit keys (via [`go-encryptions/xts`](https://github.com/go-encryptions/xts)) to open VeraCrypt volumes.

## Install

```sh
go get github.com/go-encryptions/serpent
```

## Usage

```go
import "github.com/go-encryptions/serpent"

block, err := serpent.NewCipher(key) // 16, 24 or 32 bytes
if err != nil {
	// a serpent.KeySizeError for any other length
}
block.Encrypt(dst[:16], src[:16]) // dst and src may be the same slice
block.Decrypt(dst[:16], src[:16]) // a buffer under 16 bytes panics
```

The contract is that of `cipher.Block`: in-place operation is allowed and short buffers panic. `serpent.BlockSize` is 16.

## Byte order

Serpent has two byte-order conventions. This package uses the **standard** one, that of Botan, VeraCrypt and the Linux `serpent` algorithm: the key and the block are read as little-endian 32-bit words. The reversed order (Linux `tnepres`, and the original submission's test files) is not provided.

The vectors in `testdata/botan-serpent.vec` are Botan's `src/tests/data/block/serpent.vec`, produced with Botan's standard order, and all 1047 pass, so they confirm that order. I did not obtain the NESSIE vector files, so no NESSIE vector is claimed.

## Verification

- `testdata/botan-serpent.vec`: Botan's own Serpent vectors, 1047 keys (261 at 128 bits, 327 at 192, 459 at 256), each over one or more blocks, encrypted and decrypted.
- `testdata/botan-diff.vec`: a differential corpus of 750 random keys and blocks (250 per key size, plus all-zero and all-one keys) generated from the Botan 3.14.1 command line by `internal/genbotan` (`go run ./internal/genbotan`). Regenerating needs `botan` on the `PATH`.
- `FuzzRoundTrip` cross-checks `Encrypt` and `Decrypt` round trips on every key length and the refusal of other lengths; CI runs it for 60 seconds, and its corpus is in `testdata/fuzz`.
- CI: race detector and a 100 % statement-coverage gate on amd64 and arm64; the same tests under QEMU on big-endian s390x and on riscv64; `govulncheck`.

## Implementation

The S-box expressions are Dag Arne Osvik's bitsliced forms as used by [Botan's `serpent_sbox.h`](https://github.com/randombit/botan/tree/master/src/lib/block/serpent) (BSD-2-Clause); the structure of the rounds and of the key schedule follows Botan's `serpent.cpp`. The linear transformation, the round structure, the key schedule (golden-ratio constant `0x9e3779b9`, a short key padded with a single 1 bit, prekeys turned into round keys by the S-boxes in bitslice mode) are those of sections 3 and 4 of the Serpent submission. Linux's GPL `serpent_generic.c` was not used.

Bibliography opened for this work: the Serpent AES submission (`serpent.pdf`, sections 3 and 4, [the page](https://www.cl.cam.ac.uk/~rja14/serpent.html)); Botan `serpent.cpp`, `serpent_sbox.h` and `serpent.vec`.

## Performance

`BenchmarkEncrypt` and `BenchmarkDecrypt` loop the block over a 4 KiB buffer, the shape of one XTS sector, with no allocation. The reference is Botan 3.14.1 (`botan speed --buf-size=4096 Serpent`, wrapped as Go benchmarks by `internal/botanbench` so that `abbench` can interleave it). Apple M4 Max (arm64), one core (`GOMAXPROCS=1`), 6 interleaved rounds by `abbench --max-load 8` (2 rounds discarded for load, per run), compared with `benchstat`; every result file holds 12 `^Benchmark` lines.

| 4 KiB, per call | this package | Botan, NEON (default) | Botan, scalar (`--clear-cpuid=neon`) |
|---|---|---|---|
| Encrypt | 32.75 µs (119 MiB/s) | 15.92 µs (245 MiB/s), **2.1x faster** | 30.76 µs ± 39 %, 1.06x faster |
| Decrypt | 29.93 µs (131 MiB/s) | 12.15 µs (321 MiB/s), **2.5x faster** | 26.87 µs ± 76 %, 1.11x faster |

Times are per 4 KiB call, so lower is better; the "faster" figures are Botan's advantage. The scalar column was measured while the machine's load kept moving, and its spread is wide (± 39 % and ± 76 %): read it as "same order as this package", not as a precise ratio. Botan's default build uses NEON bitslicing over several blocks at once; this package runs one block at a time in scalar Go, so **it is slower than the reference**. The SIMD follow-up is [issue #2](https://github.com/go-encryptions/serpent/issues/2).

Reproduce: `go test -c -o serpent.test .`, `go test -c -o botan.test ./internal/botanbench`, then `abbench --base ./serpent.test --head ./botan.test --max-load 8 -n 6 -- -test.bench . -test.run '^$'` (add `--head-arg=-botan.clear-cpuid=neon` for the scalar column).

## License

BSD-3-Clause © the go-encryptions/serpent authors.
