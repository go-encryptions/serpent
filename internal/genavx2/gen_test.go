package main

import (
	"bytes"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readParent(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The committed kernels are exactly what the generator writes for the
// committed S-boxes: a hand edit of the .s, or an edit of sbox.go without
// `go generate`, fails here.
func TestCommittedKernelsAreCurrent(t *testing.T) {
	got, err := Generate(readParent(t, "sbox.go"))
	if err != nil {
		t.Fatal(err)
	}
	if want := string(readParent(t, "serpent_avx2_amd64.s")); got != want {
		t.Fatal("serpent_avx2_amd64.s is stale: run `go generate ./...` in the serpent module")
	}
}

func TestCommittedAVX512KernelsAreCurrent(t *testing.T) {
	got, err := GenerateAVX512()
	if err != nil {
		t.Fatal(err)
	}
	if want := string(readParent(t, "serpent_avx512_amd64.s")); got != want {
		t.Fatal("serpent_avx512_amd64.s is stale: run `go generate ./...` in the serpent module")
	}
	for _, want := range []string{
		"//go:build amd64 && !purego", "TEXT ·encryptBlocksAVX512x16(SB)", "TEXT ·decryptBlocksAVX512x48(SB)",
		"TEXT ·hasAVX512F(SB)", "VPTERNLOGD", "VPROLD", "VPXORD.BCST", "VZEROUPPER",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated text lacks %q", want)
		}
	}
	// No spills, no stack: every value stays in a ZMM register.
	if strings.Contains(got, "(SP)") {
		t.Error("generated text uses the stack")
	}
}

// evalGo interprets an S-box of sbox.go on 32 independent bit lanes.
func evalGo(t *testing.T, sb *sbox, in [4]uint32) [4]uint32 {
	t.Helper()
	env := map[string]uint32{}
	for i, p := range sb.params {
		env[p] = in[i]
	}
	val := func(e ast.Expr) uint32 { return env[e.(*ast.Ident).Name] }
	for _, st := range sb.body {
		as := st.(*ast.AssignStmt)
		lhs := as.Lhs[0].(*ast.Ident).Name
		switch as.Tok {
		case token.DEFINE, token.ASSIGN:
			if u, ok := as.Rhs[0].(*ast.UnaryExpr); ok {
				env[lhs] = ^val(u.X)
			} else {
				env[lhs] = val(as.Rhs[0])
			}
		case token.AND_ASSIGN:
			env[lhs] &= val(as.Rhs[0])
		case token.OR_ASSIGN:
			env[lhs] |= val(as.Rhs[0])
		case token.XOR_ASSIGN:
			env[lhs] ^= val(as.Rhs[0])
		default:
			t.Fatalf("unsupported %s", as.Tok)
		}
	}
	var out [4]uint32
	for i, r := range sb.results {
		out[i] = env[r]
	}
	return out
}

// Botan's ternary-logic tables compute exactly the S-boxes of sbox.go: each
// of the sixteen, on random 32-lane words (every lane is an independent 4-bit
// S-box input) and on the exhaustive 16 input nibbles.
func TestTernarySboxesEqualTheGoSboxes(t *testing.T) {
	sbs, err := parseSboxes(readParent(t, "sbox.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ternSboxes) != 16 {
		t.Fatalf("%d ternary S-boxes", len(ternSboxes))
	}
	evalTern := func(name string, in [4]uint32) [4]uint32 {
		env := map[string]uint32{"a": in[0], "b": in[1], "c": in[2], "d": in[3]}
		for _, st := range ternSboxes[name] {
			a, b, c := env[st.a], env[st.b], env[st.c]
			var r uint32
			for lane := 0; lane < 32; lane++ {
				idx := (a>>lane&1)<<2 | (b>>lane&1)<<1 | (c >> lane & 1)
				r |= uint32(st.table>>idx&1) << lane
			}
			env[st.dst] = r
		}
		return [4]uint32{env["o0"], env["o1"], env["o2"], env["o3"]}
	}
	rng := uint64(0x9e3779b97f4a7c15)
	next := func() uint32 {
		rng = rng*6364136223846793005 + 1442695040888963407
		return uint32(rng >> 32)
	}
	for name := range ternSboxes {
		sb := sbs[name]
		if sb == nil {
			t.Fatalf("no Go S-box %s", name)
		}
		var ex [4]uint32 // lane v holds input nibble v (twice over 32 lanes)
		for v := 0; v < 32; v++ {
			for bit := 0; bit < 4; bit++ {
				ex[bit] |= uint32(v>>bit&1) << v
			}
		}
		if evalTern(name, ex) != evalGo(t, sb, ex) {
			t.Errorf("%s: differs on the exhaustive inputs", name)
		}
		for i := 0; i < 200; i++ {
			in := [4]uint32{next(), next(), next(), next()}
			if evalTern(name, in) != evalGo(t, sb, in) {
				t.Fatalf("%s: differs on random input %x", name, in)
			}
		}
	}
}

func TestPermuteTable(t *testing.T) {
	// Identity, and swapping operands 0 and 1 of "a ? b : c" (0xca) gives
	// "second ? first : third" (0xe2).
	if got := permuteTable(0xca, [3]int{0, 1, 2}); got != 0xca {
		t.Errorf("identity gave %#x", got)
	}
	if got := permuteTable(0xca, [3]int{1, 0, 2}); got != 0xe2 {
		t.Errorf("swap gave %#x, want 0xe2", got)
	}
	// Three-way XOR is symmetric.
	if got := permuteTable(0x96, [3]int{2, 1, 0}); got != 0x96 {
		t.Errorf("xor3 permuted to %#x", got)
	}
}

func TestKernel512Refusals(t *testing.T) {
	if _, err := kernel512("k", false, 0); err == nil {
		t.Error("zero groups accepted")
	}
	if _, err := kernel512("k", false, 4); err == nil {
		t.Error("four groups accepted")
	}
	saved := ternSboxes["sboxE0"]
	defer func() { ternSboxes["sboxE0"] = saved }()
	delete(ternSboxes, "sboxE0")
	if _, err := kernel512("k", false, 1); err == nil {
		t.Error("a missing S-box accepted")
	}
	ternSboxes["sboxE0"] = []ternStep{{"t0", 0x96, "a", "b", "zz"}}
	if _, err := kernel512("k", false, 1); err == nil {
		t.Error("an unknown operand accepted")
	}
	ternSboxes["sboxE0"] = []ternStep{{"t0", 0x96, "a", "b", "c"}}
	if _, err := kernel512("k", false, 1); err == nil {
		t.Error("an S-box without outputs accepted")
	}
	ternSboxes["sboxE0"] = saved
	// Decrypt side: break D7 the same ways.
	d7 := ternSboxes["sboxD7"]
	defer func() { ternSboxes["sboxD7"] = d7 }()
	delete(ternSboxes, "sboxD7")
	if _, err := kernel512("k", true, 1); err == nil {
		t.Error("a missing decrypt S-box accepted")
	}
}

func TestGeneratedShape(t *testing.T) {
	text, err := Generate(readParent(t, "sbox.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"//go:build amd64 && !purego",
		"TEXT ·encryptBlocksAVX2x8(SB)", "TEXT ·decryptBlocksAVX2x8(SB)",
		"TEXT ·encryptBlocksAVX2x16(SB)", "TEXT ·decryptBlocksAVX2x16(SB)",
		"TEXT ·hasAVX2(SB)", "VZEROUPPER",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated text lacks %q", want)
		}
	}
	// Only Y registers and general registers: no spill, no X or Z registers.
	for _, bad := range []string{" X0", " Z0", "(SP)"} {
		if strings.Contains(text, bad) {
			t.Errorf("generated text contains %q", bad)
		}
	}
}

func TestGenerateRefusals(t *testing.T) {
	src := string(readParent(t, "sbox.go"))
	cases := map[string]string{
		"syntax error":     "package x\nfunc (",
		"too few sboxes":   "package x\n",
		"unsupported stmt": strings.Replace(src, "b &= d\n", "b = b + d\n", 1),
		"bad return":       strings.Replace(src, "\treturn a, b, c, d\n}\n\nfunc sboxE1", "\treturn a, b, c\n}\n\nfunc sboxE1", 1),
		"unknown name":     strings.Replace(src, "b &= d\n", "b &= zz\n", 1),
		"non-name result":  strings.Replace(src, "\treturn a, b, c, d\n}\n\nfunc sboxE1", "\treturn a, b, c, 1\n}\n\nfunc sboxE1", 1),
		"unsupported op":   strings.Replace(src, "b &= d\n", "b <<= 3\n", 1),
		"too many params":  strings.Replace(src, "func sboxE0(a, b, c, d uint32)", "func sboxE0(a, b, c, d, e uint32)", 1),
		"too few params":   strings.Replace(src, "func sboxE0(a, b, c, d uint32)", "func sboxE0(a, b, c uint32)", 1),
	}
	for name, s := range cases {
		if s == src && name != "syntax error" && name != "too few sboxes" {
			t.Fatalf("%s: the case did not change the source", name)
		}
		if _, err := Generate([]byte(s)); err == nil {
			t.Errorf("%s: Generate accepted it", name)
		}
	}
}

func TestKernelRefusals(t *testing.T) {
	sb, err := parseSboxes(readParent(t, "sbox.go"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kernel(sb, "k", false, 3); err == nil {
		t.Error("three groups accepted")
	}
	if _, err := kernel(sb, "k", false, 0); err == nil {
		t.Error("zero groups accepted")
	}
}

func TestRootCmd(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "k.s")
	var stdout, stderr bytes.Buffer
	cmd := RootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	out512 := filepath.Join(dir, "k512.s")
	cmd.SetArgs([]string{"--sbox", filepath.Join("..", "..", "sbox.go"), "--out", out, "--out512", out512})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, readParent(t, "serpent_avx2_amd64.s")) {
		t.Error("the command wrote something other than the committed kernels")
	}
	got512, err := os.ReadFile(out512)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got512, readParent(t, "serpent_avx512_amd64.s")) {
		t.Error("the command wrote something other than the committed AVX-512 kernels")
	}
	if !strings.Contains(stdout.String(), "wrote") {
		t.Errorf("no confirmation: %q", stdout.String())
	}
}

func TestMainReportsAndExits(t *testing.T) {
	saved := osExit
	defer func() { osExit = saved }()
	code := -1
	osExit = func(c int) { code = c }

	savedArgs := os.Args
	defer func() { os.Args = savedArgs }()
	os.Args = []string{"genavx2", "--sbox", filepath.Join(t.TempDir(), "missing.go")}
	main()
	if code != 1 {
		t.Fatalf("exit code %d, want 1 for a missing S-box file", code)
	}

	code = -1
	dir := t.TempDir()
	os.Args = []string{"genavx2", "--sbox", filepath.Join("..", "..", "sbox.go"), "--out", filepath.Join(dir, "k.s"), "--out512", filepath.Join(dir, "k512.s")}
	main()
	if code != -1 {
		t.Fatalf("exit called with %d on success", code)
	}
}

func TestRootCmdErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.go")
	if err := os.WriteFile(bad, []byte("package x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"missing sbox":      {"--sbox", filepath.Join(dir, "none.go")},
		"no sboxes":         {"--sbox", bad},
		"unwritable out":    {"--sbox", filepath.Join("..", "..", "sbox.go"), "--out", filepath.Join(dir, "no", "such", "k.s")},
		"unwritable out512": {"--sbox", filepath.Join("..", "..", "sbox.go"), "--out", filepath.Join(dir, "k.s"), "--out512", filepath.Join(dir, "no", "such", "k.s")},
		"positional extra":  {"extra"},
	} {
		cmd := RootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
