// Package main generates serpent_avx2_amd64.s: the AVX2 kernels that run
// Serpent over 8 (or 16) blocks at a time, with go-asmgen.
//
// The S-box expressions are NOT retyped here. They are read from sbox.go with
// go/parser (the Osvik forms, as in Botan's src/lib/block/serpent/
// serpent_sbox.h), and each statement is translated into single-assignment
// vector code, so the kernel and the pure-Go oracle cannot drift apart: a
// transcription slip would need the same slip in both.
//
// Layout (Botan's serpent_simd8x32.cpp, lines 51-172): the 128 input bytes
// are loaded as four 32-byte vectors and transposed in 4x4 blocks of 32-bit
// words, so that register i holds word i of all eight blocks; the 32 rounds
// then run on four registers, every instruction acting on eight blocks.
//
// One group of eight blocks is a single dependency chain. With groups=2 the
// instruction streams of two independent groups are interleaved one
// instruction at a time, so the out-of-order core always finds independent
// work; a linear-scan allocator over the merged stream assigns the sixteen YMM
// registers and refuses (panics) rather than spill.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"

	"github.com/go-asmgen/asmgen/amd64"
	"github.com/go-asmgen/asmgen/emit"
)

type vreg int

type insn struct {
	op       string // xor and or shl shr bcast
	dst      vreg
	a, b     vreg
	imm      int // shift count, or the round-key word index for bcast
	hasA     bool
	hasB     bool
	instrIdx int
}

// stream is the single-assignment code of one group of eight blocks.
type stream struct {
	next  *vreg // shared counter, so that vregs are unique across groups
	ones  vreg
	insns []insn
}

func (s *stream) fresh() vreg { *s.next++; return *s.next }

func (s *stream) bin(op string, a, b vreg) vreg {
	d := s.fresh()
	s.insns = append(s.insns, insn{op: op, dst: d, a: a, b: b, hasA: true, hasB: true})
	return d
}

func (s *stream) sh(op string, a vreg, n int) vreg {
	d := s.fresh()
	s.insns = append(s.insns, insn{op: op, dst: d, a: a, imm: n, hasA: true})
	return d
}

func (s *stream) xor(a, b vreg) vreg { return s.bin("xor", a, b) }
func (s *stream) and(a, b vreg) vreg { return s.bin("and", a, b) }
func (s *stream) or(a, b vreg) vreg  { return s.bin("or", a, b) }
func (s *stream) not(a vreg) vreg    { return s.xor(a, s.ones) }

func (s *stream) rotl(a vreg, n int) vreg {
	return s.or(s.sh("shl", a, n), s.sh("shr", a, 32-n))
}

// keymix returns x ^ rk[word], the round-key word broadcast to every lane.
func (s *stream) keymix(x vreg, word int) vreg {
	d := s.fresh()
	s.insns = append(s.insns, insn{op: "bcast", dst: d, imm: word})
	return s.xor(x, d)
}

type state [4]vreg

func (s *stream) keyAll(x state, round int) state {
	for i := range x {
		x[i] = s.keymix(x[i], 4*round+i)
	}
	return x
}

// lt is Serpent's linear transformation (serpent.go lt; Botan serpent_fn.h:34).
func (s *stream) lt(x state) state {
	a, b, c, d := x[0], x[1], x[2], x[3]
	a = s.rotl(a, 13)
	c = s.rotl(c, 3)
	b = s.xor(s.xor(b, a), c)
	d = s.xor(s.xor(d, c), s.sh("shl", a, 3))
	b = s.rotl(b, 1)
	d = s.rotl(d, 7)
	a = s.xor(s.xor(a, b), d)
	c = s.xor(s.xor(c, d), s.sh("shl", b, 7))
	a = s.rotl(a, 5)
	c = s.rotl(c, 22)
	return state{a, b, c, d}
}

// ilt is the inverse (serpent.go ilt; Botan serpent_fn.h:51); rotr(x,n) is
// rotl(x,32-n).
func (s *stream) ilt(x state) state {
	a, b, c, d := x[0], x[1], x[2], x[3]
	c = s.rotl(c, 32-22)
	a = s.rotl(a, 32-5)
	c = s.xor(s.xor(c, d), s.sh("shl", b, 7))
	a = s.xor(s.xor(a, b), d)
	d = s.rotl(d, 32-7)
	b = s.rotl(b, 32-1)
	d = s.xor(s.xor(d, c), s.sh("shl", a, 3))
	b = s.xor(s.xor(b, a), c)
	c = s.rotl(c, 32-3)
	a = s.rotl(a, 32-13)
	return state{a, b, c, d}
}

// sbox translates the body of one sboxE?/sboxD? function of sbox.go.
type sbox struct {
	params  [4]string
	body    []ast.Stmt
	results [4]string
}

func parseSboxes(src []byte) (map[string]*sbox, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sbox.go", src, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]*sbox{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(fd.Name.Name, "sbox") {
			continue
		}
		sb := &sbox{}
		n := 0
		for _, p := range fd.Type.Params.List {
			for _, id := range p.Names {
				if n >= 4 {
					return nil, fmt.Errorf("%s: more than four parameters", fd.Name.Name)
				}
				sb.params[n] = id.Name
				n++
			}
		}
		if n != 4 {
			return nil, fmt.Errorf("%s: %d parameters, want 4", fd.Name.Name, n)
		}
		stmts := fd.Body.List
		ret, ok := stmts[len(stmts)-1].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 4 {
			return nil, fmt.Errorf("%s: last statement is not a four-value return", fd.Name.Name)
		}
		for i, r := range ret.Results {
			id, ok := r.(*ast.Ident)
			if !ok {
				return nil, fmt.Errorf("%s: return value %d is not a name", fd.Name.Name, i)
			}
			sb.results[i] = id.Name
		}
		sb.body = stmts[:len(stmts)-1]
		out[fd.Name.Name] = sb
	}
	return out, nil
}

// apply runs the S-box on x and returns the four output words. Names that
// alias one another (t0 := b, a = b) simply share a vreg: no instruction is
// emitted for a copy, because every operation writes a fresh vreg.
func (sb *sbox) apply(s *stream, name string, x state) (state, error) {
	env := map[string]vreg{}
	for i, p := range sb.params {
		env[p] = x[i]
	}
	get := func(e ast.Expr) (vreg, error) {
		id, ok := e.(*ast.Ident)
		if !ok {
			return 0, fmt.Errorf("%s: operand %T is not a name", name, e)
		}
		v, ok := env[id.Name]
		if !ok {
			return 0, fmt.Errorf("%s: %s used before it is set", name, id.Name)
		}
		return v, nil
	}
	for _, st := range sb.body {
		as, ok := st.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return state{}, fmt.Errorf("%s: unsupported statement %T", name, st)
		}
		lhs, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return state{}, fmt.Errorf("%s: assignment to a non-name", name)
		}
		switch as.Tok {
		case token.DEFINE, token.ASSIGN:
			if u, ok := as.Rhs[0].(*ast.UnaryExpr); ok && u.Op == token.XOR {
				v, err := get(u.X)
				if err != nil {
					return state{}, err
				}
				env[lhs.Name] = s.not(v)
				continue
			}
			v, err := get(as.Rhs[0])
			if err != nil {
				return state{}, err
			}
			env[lhs.Name] = v
		case token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN:
			l, err := get(lhs)
			if err != nil {
				return state{}, err
			}
			r, err := get(as.Rhs[0])
			if err != nil {
				return state{}, err
			}
			switch as.Tok {
			case token.AND_ASSIGN:
				env[lhs.Name] = s.and(l, r)
			case token.OR_ASSIGN:
				env[lhs.Name] = s.or(l, r)
			default:
				env[lhs.Name] = s.xor(l, r)
			}
		default:
			return state{}, fmt.Errorf("%s: unsupported operator %s", name, as.Tok)
		}
	}
	var out state
	for i, r := range sb.results {
		v, ok := env[r]
		if !ok {
			return state{}, fmt.Errorf("%s: result %s never set", name, r)
		}
		out[i] = v
	}
	return out, nil
}

// encrypt and decrypt emit the 32 rounds for one group.
func (s *stream) encrypt(sb map[string]*sbox, x state) (state, error) {
	for i := 0; i < 32; i++ {
		x = s.keyAll(x, i)
		var err error
		if x, err = sb[fmt.Sprintf("sboxE%d", i%8)].apply(s, fmt.Sprintf("sboxE%d", i%8), x); err != nil {
			return x, err
		}
		if i < 31 {
			x = s.lt(x)
		}
	}
	return s.keyAll(x, 32), nil
}

func (s *stream) decrypt(sb map[string]*sbox, x state) (state, error) {
	x = s.keyAll(x, 32)
	for i := 31; i >= 0; i-- {
		var err error
		if x, err = sb[fmt.Sprintf("sboxD%d", i%8)].apply(s, fmt.Sprintf("sboxD%d", i%8), x); err != nil {
			return x, err
		}
		x = s.keyAll(x, i)
		if i > 0 {
			x = s.ilt(x)
		}
	}
	return x, nil
}

// kernel builds one TEXT block: func name(rk *uint32, dst, src *byte, n int),
// which runs n chunks of 8*groups blocks (n >= 0).
func kernel(sb map[string]*sbox, name string, dec bool, groups int) (*emit.Function, error) {
	if groups < 1 || groups > 2 {
		return nil, fmt.Errorf("groups %d: only 1 or 2 fit in sixteen registers", groups)
	}
	var counter vreg
	onesReg := amd64.Y15
	ones := vreg(0) // vreg 0 is the constant, pinned to Y15 for the whole kernel

	streams := make([]*stream, groups)
	pins := map[vreg]amd64.YReg{ones: onesReg}
	inputs := make([]state, groups)
	outputs := make([]state, groups)
	for g := range streams {
		streams[g] = &stream{next: &counter, ones: ones}
		for i := range inputs[g] {
			inputs[g][i] = streams[g].fresh()
			pins[inputs[g][i]] = amd64.YReg(4*g + i)
		}
		var err error
		if dec {
			outputs[g], err = streams[g].decrypt(sb, inputs[g])
		} else {
			outputs[g], err = streams[g].encrypt(sb, inputs[g])
		}
		if err != nil {
			return nil, err
		}
	}

	// Merge: one instruction from each group in turn.
	var merged []insn
	for k := 0; ; k++ {
		more := false
		for _, s := range streams {
			if k < len(s.insns) {
				merged = append(merged, s.insns[k])
				more = true
			}
		}
		if !more {
			break
		}
	}

	// Linear scan. lastUse[v] is the index of the last instruction reading v;
	// outputs and the ones constant live to the end.
	lastUse := map[vreg]int{ones: len(merged)}
	for i, in := range merged {
		if in.hasA {
			lastUse[in.a] = i
		}
		if in.hasB {
			lastUse[in.b] = i
		}
	}
	lastUse[ones] = len(merged) // the loop above saw it as the operand of every NOT
	seen := map[vreg]bool{}
	for g := range outputs {
		for _, v := range outputs[g] {
			if seen[v] {
				return nil, fmt.Errorf("group %d: two output words share one value", g)
			}
			seen[v] = true
			lastUse[v] = len(merged)
		}
	}
	phys := map[vreg]amd64.YReg{}
	busy := map[amd64.YReg]bool{}
	for v, r := range pins {
		phys[v] = r
		busy[r] = true
	}
	alloc := func() (amd64.YReg, error) {
		for r := amd64.Y0; r <= amd64.Y15; r++ {
			if !busy[r] {
				busy[r] = true
				return r, nil
			}
		}
		return 0, fmt.Errorf("out of YMM registers")
	}
	free := func(v vreg) {
		if r, ok := phys[v]; ok && lastUse[v] != len(merged) {
			delete(busy, r)
		}
	}

	f := amd64.NewFunc(name, amd64.Layout(
		[]string{"rk", "dst", "src", "n"},
		[]amd64.Type{amd64.Ptr, amd64.Ptr, amd64.Ptr, amd64.Int64}, nil, nil), 0)
	f.LoadArg("rk", "DX").LoadArg("dst", "DI").LoadArg("src", "SI").LoadArg("n", "CX")
	f.Raw("TESTQ CX, CX").Raw("JZ done").Ones(onesReg).Label("loop")

	// Prologue: load the 128 bytes of each group and transpose them. The
	// scratch pair is two registers outside every group's four.
	t0, t1 := amd64.YReg(4*groups), amd64.YReg(4*groups+1)
	for g := 0; g < groups; g++ {
		for i := 0; i < 4; i++ {
			f.VMOVDQU(amd64.YReg(4*g+i), fmt.Sprintf("%d(SI)", 128*g+32*i))
		}
		f.Transpose4x32(amd64.YReg(4*g), amd64.YReg(4*g+1), amd64.YReg(4*g+2), amd64.YReg(4*g+3), t0, t1)
	}

	for i, in := range merged {
		// Free the sources that die here before allocating the destination, so
		// the destination can reuse a source's register (VEX is 3-operand).
		var srcs []vreg
		if in.hasA {
			srcs = append(srcs, in.a)
		}
		if in.hasB && in.b != in.a {
			srcs = append(srcs, in.b)
		}
		ra, rb := phys[in.a], phys[in.b]
		for _, v := range srcs {
			if lastUse[v] == i {
				free(v)
			}
		}
		if _, ok := lastUse[in.dst]; !ok {
			return nil, fmt.Errorf("instruction %d (%s) defines a value nobody reads", i, in.op)
		}
		rd, err := alloc()
		if err != nil {
			return nil, fmt.Errorf("instruction %d of %d: %w", i, len(merged), err)
		}
		phys[in.dst] = rd
		switch in.op {
		case "xor":
			f.VPXOR(rd, ra, rb)
		case "and":
			f.VPAND(rd, ra, rb)
		case "or":
			f.VPOR(rd, ra, rb)
		case "shl":
			f.VPSLLD(rd, ra, in.imm)
		case "shr":
			f.VPSRLD(rd, ra, in.imm)
		case "bcast":
			f.VPBROADCASTD(rd, fmt.Sprintf("%d(DX)", 4*in.imm))
		default:
			return nil, fmt.Errorf("unknown op %q", in.op)
		}
	}

	// Epilogue: the outputs sit in whichever registers the allocator left
	// them in; transpose each group back and store the 128 bytes.
	var outRegs []amd64.YReg
	for g := range outputs {
		for _, v := range outputs[g] {
			outRegs = append(outRegs, phys[v])
		}
	}
	var spare []amd64.YReg
	used := map[amd64.YReg]bool{}
	for _, r := range outRegs {
		used[r] = true
	}
	for r := amd64.Y0; r <= amd64.Y15 && len(spare) < 2; r++ {
		if !used[r] {
			spare = append(spare, r)
		}
	}
	if len(spare) < 2 {
		return nil, fmt.Errorf("no scratch registers left for the final transpose")
	}
	for g := 0; g < groups; g++ {
		r := outRegs[4*g : 4*g+4]
		f.Transpose4x32(r[0], r[1], r[2], r[3], spare[0], spare[1])
		for i := 0; i < 4; i++ {
			f.VMOVDQUStore(fmt.Sprintf("%d(DI)", 128*g+32*i), r[i])
		}
	}
	f.Raw("ADDQ $%d, SI", 128*groups).Raw("ADDQ $%d, DI", 128*groups).Raw("DECQ CX").Raw("JNZ loop")
	f.Label("done").VZEROUPPER().Ret()
	return f.Func(), nil
}

// Generate returns the text of serpent_avx2_amd64.s for the S-boxes in sbox.go.
func Generate(sboxSrc []byte) (string, error) {
	sb, err := parseSboxes(sboxSrc)
	if err != nil {
		return "", err
	}
	var names []string
	for n := range sb {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) != 16 {
		return "", fmt.Errorf("found %d S-boxes (%v), want 16", len(names), names)
	}
	file := emit.NewFile("amd64 && !purego")
	for _, k := range []struct {
		name   string
		dec    bool
		groups int
	}{
		{"encryptBlocksAVX2x8", false, 1},
		{"decryptBlocksAVX2x8", true, 1},
		{"encryptBlocksAVX2x16", false, 2},
		{"decryptBlocksAVX2x16", true, 2},
	} {
		fn, err := kernel(sb, k.name, k.dec, k.groups)
		if err != nil {
			return "", fmt.Errorf("%s: %w", k.name, err)
		}
		file.Add(fn)
	}
	file.Add(amd64.FeatureProbe("hasAVX2", amd64.AVX2))
	return file.String(), nil
}
