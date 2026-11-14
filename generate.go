package serpent

// The AVX2 kernels of serpent_avx2_amd64.s are generated, on any host, from
// the S-boxes of sbox.go by a separate module so that go-asmgen stays out of
// this module's requirements. internal/genavx2's own test fails when the
// committed file is stale.
//
//go:generate go run -C internal/genavx2 .
