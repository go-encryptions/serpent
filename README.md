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

The returned cipher also has `EncryptBlocks(dst, src []byte)` and `DecryptBlocks(dst, src []byte)`, which process every 16-byte block of `src` independently (ECB), four at a time in pure Go, and sixteen or eight at a time with AVX2 kernels on amd64 (see Performance), and are 2.5x (arm64, pure Go) to 8.5x (amd64, AVX2) faster than a loop over `Encrypt`. `len(src)` must be a multiple of 16 and `dst` at least as long (otherwise they panic); `dst` and `src` must overlap entirely or not at all.

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

`BenchmarkEncrypt` and `BenchmarkDecrypt` loop `Encrypt`/`Decrypt` over a 4 KiB buffer, the shape of one XTS sector; `BenchmarkEncryptBlocks` and `BenchmarkDecryptBlocks` make one `EncryptBlocks`/`DecryptBlocks` call on the same buffer. None allocates. The reference is Botan 3.14.1 (`botan speed --buf-size=4096 Serpent`, wrapped as Go benchmarks by `internal/botanbench` so that `abbench` can interleave it). Apple M4 Max (arm64), one core (`GOMAXPROCS=1`), 6 interleaved rounds by `abbench --max-load 8`, summarised with `benchstat`; every result file holds 24 `^Benchmark` lines.

| 4 KiB, per call | this package, per block | this package, `EncryptBlocks`/`DecryptBlocks` | Botan, NEON (default) |
|---|---|---|---|
| Encrypt | 32.38 µs ± 6 % (121 MiB/s) | **12.21 µs ± 2 % (320 MiB/s)** | 15.69 µs ± 8 % (249 MiB/s) |
| Decrypt | 29.38 µs ± 4 % (133 MiB/s) | **11.92 µs ± 2 % (328 MiB/s)** | 11.96 µs ± 5 % (327 MiB/s) |

Times are per 4 KiB call, so lower is better. The batch path is 2.7x (encrypt) and 2.5x (decrypt) faster than the per-block path, 1.28x faster than Botan's NEON build when encrypting and level with it (11.92 vs 11.96 µs, inside the noise) when decrypting. On arm64 it is pure Go, with no assembly and no SIMD: `EncryptBlocks` and `DecryptBlocks` push four blocks through the rounds side by side, as sixteen separate variables, so that the processor has four independent dependency chains and the whole state stays in registers. Callers that process many blocks, such as [`go-encryptions/xts`](https://github.com/go-encryptions/xts), use it automatically.

### amd64 (AVX2)

On amd64 with AVX2, `EncryptBlocks` and `DecryptBlocks` run generated assembly: Botan's 8x32 layout (`serpent_simd8x32.cpp`: load, 4x4 transpose of 32-bit words, 32 rounds on four YMM registers, transpose, store), and a 16-block kernel that interleaves two independent groups instruction by instruction, because one group is a single dependency chain. `internal/genavx2` (its own module) generates the kernels with [go-asmgen](https://github.com/go-asmgen/asmgen) from the S-box statements of `sbox.go` themselves, so the pure-Go code stays the oracle; `go generate` rewrites `serpent_avx2_amd64.s` and CI fails if it is stale. CPU and OS support are probed at start-up; without AVX2, with the `purego` tag, and on other architectures the four-block Go loops run, with the same output.

AMD Ryzen 9 7950X (Zen 4), linux/amd64, core 4 (`taskset -c 4`), Botan 3.14.1 built with clang 22.1.8, 4 KiB, MiB/s (higher is better), median of the interleaved rounds started at a 1-minute load of at most 2:

| | per block | pure-Go batch of 4 (before) | **AVX2 batch (this)** | Botan AVX2 | Botan AVX-512 |
|---|---|---|---|---|---|
| Encrypt | 155 | 240 | **1312** | 934 | 1691 |
| Decrypt | 162 | 230 | **1329** | 1078 | 2021 |

The AVX2 batch is 1.40x the speed of Botan's AVX2 build when encrypting and 1.23x when decrypting, and 78 % of Botan's AVX-512 build (66 % when decrypting); the gap to AVX-512 is its three-operand `vpternlogd` and native rotates, which AVX2 lacks. The 8-block kernel alone runs at about 990 MiB/s (`BenchmarkKernels`), level with Botan AVX2; the 16-block one adds a third.

With AVX-512F the dispatcher goes AVX-512 > AVX2 > Go: kernels of 16, 32 and 48 blocks per chunk (one ZMM register holds one state word of 16 blocks), whose S-boxes are Botan's `vpternlogd` tables (one instruction per three-input term; `internal/convbotan` converts them, a test proves them equal to the Go S-boxes) with the native `vprold` rotate. Same machine and method, 7 rounds all at load below 1: **2360 MiB/s encrypting and 2689 decrypting, against 1696 and 2030 for Botan's AVX-512 build (1.39x and 1.32x)**.

Reproduce: `go test -c -o serpent.test .`, `go test -c -o botan.test ./internal/botanbench`, then `abbench --base ./serpent.test --head ./botan.test --max-load 8 -n 6 -- -test.bench . -test.run '^$'`. The two binaries are different packages, so run `benchstat` on `base.txt` and `head.txt` one at a time.

## License

BSD-3-Clause © the go-encryptions/serpent authors.
