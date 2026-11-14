package main

import (
	"bytes"
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
	cmd.SetArgs([]string{"--sbox", filepath.Join("..", "..", "sbox.go"), "--out", out})
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
	os.Args = []string{"genavx2", "--sbox", filepath.Join("..", "..", "sbox.go"), "--out", filepath.Join(dir, "k.s")}
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
		"missing sbox":     {"--sbox", filepath.Join(dir, "none.go")},
		"no sboxes":        {"--sbox", bad},
		"unwritable out":   {"--sbox", filepath.Join("..", "..", "sbox.go"), "--out", filepath.Join(dir, "no", "such", "k.s")},
		"positional extra": {"extra"},
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
