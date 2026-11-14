package main

// The AVX-512 kernels. Same layout as the AVX2 ones (Botan's
// serpent_avx512.cpp, lines 306-553: four loads, a 4x4 transpose, 32 rounds on
// four registers, transpose, store) at 16 blocks per ZMM register, with the
// two things AVX-512 has that AVX2 lacks: VPTERNLOGD, which computes any
// three-input boolean function in one instruction, so each S-box is 8 or 9
// instructions instead of 15 to 20 (the tables are Botan's, converted by
// internal/convbotan into sbox512.go); and VPROLD, the native rotate. The
// three-way XORs of the linear transformation are VPTERNLOGD 0x96, and the
// round-key XOR is VPXORD with an embedded broadcast of the key word.

import (
	"fmt"

	"github.com/go-asmgen/asmgen/amd64"
	"github.com/go-asmgen/asmgen/emit"
)

type zop struct {
	op  string // tern xorb rol shl
	dst vreg
	src []vreg
	imm int // truth table, key word index, or shift count
}

type zstream struct {
	next  *vreg
	insns []zop
}

func (s *zstream) emit(op string, imm int, src ...vreg) vreg {
	*s.next++
	d := *s.next
	s.insns = append(s.insns, zop{op: op, dst: d, src: src, imm: imm})
	return d
}

func (s *zstream) tern(table uint8, a, b, c vreg) vreg { return s.emit("tern", int(table), a, b, c) }
func (s *zstream) xor3(a, b, c vreg) vreg              { return s.tern(0x96, a, b, c) }
func (s *zstream) rol(a vreg, n int) vreg              { return s.emit("rol", n, a) }
func (s *zstream) shl(a vreg, n int) vreg              { return s.emit("shl", n, a) }
func (s *zstream) keymix(x vreg, word int) vreg        { return s.emit("xorb", word, x) }

func (s *zstream) keyAll(x state, round int) state {
	for i := range x {
		x[i] = s.keymix(x[i], 4*round+i)
	}
	return x
}

// lt is gen.go's lt with the XOR pairs fused into three-way XORs and the
// rotates native.
func (s *zstream) lt(x state) state {
	a, b, c, d := x[0], x[1], x[2], x[3]
	a = s.rol(a, 13)
	c = s.rol(c, 3)
	b = s.xor3(b, a, c)
	d = s.xor3(d, c, s.shl(a, 3))
	b = s.rol(b, 1)
	d = s.rol(d, 7)
	a = s.xor3(a, b, d)
	c = s.xor3(c, d, s.shl(b, 7))
	a = s.rol(a, 5)
	c = s.rol(c, 22)
	return state{a, b, c, d}
}

func (s *zstream) ilt(x state) state {
	a, b, c, d := x[0], x[1], x[2], x[3]
	c = s.rol(c, 32-22)
	a = s.rol(a, 32-5)
	c = s.xor3(c, d, s.shl(b, 7))
	a = s.xor3(a, b, d)
	d = s.rol(d, 32-7)
	b = s.rol(b, 32-1)
	d = s.xor3(d, c, s.shl(a, 3))
	b = s.xor3(b, a, c)
	c = s.rol(c, 32-3)
	a = s.rol(a, 32-13)
	return state{a, b, c, d}
}

// sbox applies Botan's ternary-logic S-box of the given name.
func (s *zstream) sbox(name string, x state) (state, error) {
	steps, ok := ternSboxes[name]
	if !ok {
		return state{}, fmt.Errorf("no ternary S-box %s", name)
	}
	env := map[string]vreg{"a": x[0], "b": x[1], "c": x[2], "d": x[3]}
	for _, st := range steps {
		var v [3]vreg
		for i, n := range []string{st.a, st.b, st.c} {
			r, ok := env[n]
			if !ok {
				return state{}, fmt.Errorf("%s: %s used before it is set", name, n)
			}
			v[i] = r
		}
		env[st.dst] = s.tern(st.table, v[0], v[1], v[2])
	}
	var out state
	for i, n := range []string{"o0", "o1", "o2", "o3"} {
		r, ok := env[n]
		if !ok {
			return state{}, fmt.Errorf("%s: output %s never set", name, n)
		}
		out[i] = r
	}
	return out, nil
}

func (s *zstream) encrypt(x state) (state, error) {
	for i := 0; i < 32; i++ {
		x = s.keyAll(x, i)
		var err error
		if x, err = s.sbox(fmt.Sprintf("sboxE%d", i%8), x); err != nil {
			return x, err
		}
		if i < 31 {
			x = s.lt(x)
		}
	}
	return s.keyAll(x, 32), nil
}

func (s *zstream) decrypt(x state) (state, error) {
	x = s.keyAll(x, 32)
	for i := 31; i >= 0; i-- {
		var err error
		if x, err = s.sbox(fmt.Sprintf("sboxD%d", i%8), x); err != nil {
			return x, err
		}
		x = s.keyAll(x, i)
		if i > 0 {
			x = s.ilt(x)
		}
	}
	return x, nil
}

// permuteTable returns the truth table of the same function with its
// operands reordered: new operand k is old operand perm[k].
func permuteTable(table uint8, perm [3]int) uint8 {
	var out uint8
	for idx := 0; idx < 8; idx++ {
		var old [3]int // old operand values for this new index
		bits := [3]int{(idx >> 2) & 1, (idx >> 1) & 1, idx & 1}
		for k := 0; k < 3; k++ {
			old[perm[k]] = bits[k]
		}
		if table>>(old[0]<<2|old[1]<<1|old[2])&1 == 1 {
			out |= 1 << idx
		}
	}
	return out
}

func kernel512(name string, dec bool, groups int) (*emit.Function, error) {
	if groups < 1 || groups > 3 {
		return nil, fmt.Errorf("groups %d: only 1 to 3 fit in 32 registers", groups)
	}
	var counter vreg
	streams := make([]*zstream, groups)
	pins := map[vreg]amd64.ZReg{}
	outputs := make([]state, groups)
	for g := range streams {
		streams[g] = &zstream{next: &counter}
		var in state
		for i := range in {
			counter++
			in[i] = counter
			pins[in[i]] = amd64.ZReg(4*g + i)
		}
		var err error
		if dec {
			outputs[g], err = streams[g].decrypt(in)
		} else {
			outputs[g], err = streams[g].encrypt(in)
		}
		if err != nil {
			return nil, err
		}
	}
	var merged []zop
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

	end := len(merged)
	lastUse := map[vreg]int{}
	for i, in := range merged {
		for _, v := range in.src {
			lastUse[v] = i
		}
	}
	seen := map[vreg]bool{}
	for g := range outputs {
		for _, v := range outputs[g] {
			if seen[v] {
				return nil, fmt.Errorf("group %d: two output words share one value", g)
			}
			seen[v] = true
			lastUse[v] = end
		}
	}
	phys := map[vreg]amd64.ZReg{}
	busy := map[amd64.ZReg]bool{}
	for v, r := range pins {
		phys[v] = r
		busy[r] = true
	}
	alloc := func() (amd64.ZReg, error) {
		for r := amd64.Z0; r <= amd64.Z31; r++ {
			if !busy[r] {
				busy[r] = true
				return r, nil
			}
		}
		return 0, fmt.Errorf("out of ZMM registers")
	}

	f := amd64.NewFunc(name, amd64.Layout(
		[]string{"rk", "dst", "src", "n"},
		[]amd64.Type{amd64.Ptr, amd64.Ptr, amd64.Ptr, amd64.Int64}, nil, nil), 0)
	f.LoadArg("rk", "DX").LoadArg("dst", "DI").LoadArg("src", "SI").LoadArg("n", "CX")
	f.Raw("TESTQ CX, CX").Raw("JZ done").Label("loop")

	t0, t1 := amd64.ZReg(4*groups), amd64.ZReg(4*groups+1)
	for g := 0; g < groups; g++ {
		for i := 0; i < 4; i++ {
			f.VMOVDQU32(amd64.ZReg(4*g+i), fmt.Sprintf("%d(SI)", 256*g+64*i))
		}
		f.Transpose4x32Z(amd64.ZReg(4*g), amd64.ZReg(4*g+1), amd64.ZReg(4*g+2), amd64.ZReg(4*g+3), t0, t1)
	}

	for i, in := range merged {
		if _, ok := lastUse[in.dst]; !ok {
			return nil, fmt.Errorf("instruction %d (%s) defines a value nobody reads", i, in.op)
		}
		// Operand registers, and which of them die here.
		regs := make([]amd64.ZReg, len(in.src))
		dying := -1
		for k, v := range in.src {
			regs[k] = phys[v]
			if dying < 0 && lastUse[v] == i {
				dying = k
			}
		}
		var rd amd64.ZReg
		table := uint8(in.imm)
		if in.op == "tern" {
			// VPTERNLOGD overwrites its first operand: put a dying input
			// there (the table is permuted to match), or copy one.
			perm := [3]int{0, 1, 2}
			if dying > 0 {
				perm[0], perm[dying] = dying, 0
			}
			if dying >= 0 {
				rd = regs[perm[0]]
			} else {
				var err error
				if rd, err = alloc(); err != nil {
					return nil, fmt.Errorf("instruction %d of %d: %w", i, len(merged), err)
				}
				f.VMOVDQA32(rd, regs[0])
			}
			table = permuteTable(table, perm)
			f.VPTERNLOGD(table, rd, regs[perm[1]], regs[perm[2]])
		} else {
			if dying >= 0 {
				rd = regs[0]
			} else {
				var err error
				if rd, err = alloc(); err != nil {
					return nil, fmt.Errorf("instruction %d of %d: %w", i, len(merged), err)
				}
			}
			switch in.op {
			case "rol":
				f.VPROLD(rd, regs[0], in.imm)
			case "shl":
				f.VPSLLD512(rd, regs[0], in.imm)
			case "xorb":
				f.VPXORDBcst(rd, regs[0], fmt.Sprintf("%d(DX)", 4*in.imm))
			default:
				return nil, fmt.Errorf("unknown op %q", in.op)
			}
		}
		// Free every dying source register except the one dst now owns.
		freed := map[amd64.ZReg]bool{}
		for k, v := range in.src {
			if lastUse[v] == i && regs[k] != rd && !freed[regs[k]] {
				freed[regs[k]] = true
				delete(busy, regs[k])
			}
		}
		phys[in.dst] = rd
	}

	var outRegs []amd64.ZReg
	used := map[amd64.ZReg]bool{}
	for g := range outputs {
		for _, v := range outputs[g] {
			outRegs = append(outRegs, phys[v])
			used[phys[v]] = true
		}
	}
	var spare []amd64.ZReg
	for r := amd64.Z0; r <= amd64.Z31 && len(spare) < 2; r++ {
		if !used[r] {
			spare = append(spare, r)
		}
	}
	for g := 0; g < groups; g++ {
		r := outRegs[4*g : 4*g+4]
		f.Transpose4x32Z(r[0], r[1], r[2], r[3], spare[0], spare[1])
		for i := 0; i < 4; i++ {
			f.VMOVDQU32Store(fmt.Sprintf("%d(DI)", 256*g+64*i), r[i])
		}
	}
	f.Raw("ADDQ $%d, SI", 256*groups).Raw("ADDQ $%d, DI", 256*groups).Raw("DECQ CX").Raw("JNZ loop")
	f.Label("done").VZEROUPPER().Ret()
	return f.Func(), nil
}

// GenerateAVX512 returns the text of serpent_avx512_amd64.s.
func GenerateAVX512() (string, error) {
	file := emit.NewFile("amd64 && !purego")
	for _, k := range []struct {
		name   string
		dec    bool
		groups int
	}{
		{"encryptBlocksAVX512x16", false, 1},
		{"decryptBlocksAVX512x16", true, 1},
		{"encryptBlocksAVX512x32", false, 2},
		{"decryptBlocksAVX512x32", true, 2},
		{"encryptBlocksAVX512x48", false, 3},
		{"decryptBlocksAVX512x48", true, 3},
	} {
		fn, err := kernel512(k.name, k.dec, k.groups)
		if err != nil {
			return "", fmt.Errorf("%s: %w", k.name, err)
		}
		file.Add(fn)
	}
	file.Add(amd64.FeatureProbe("hasAVX512F", amd64.AVX512F))
	return file.String(), nil
}
