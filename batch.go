package serpent

import "encoding/binary"

// The four blocks are written out as sixteen separate variables, not an
// array, so that the compiler keeps the whole state in registers and the four
// dependency chains interleave.

func checkBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("serpent: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("serpent: output smaller than input")
	}
}

// EncryptBlocks encrypts every 16-byte block of src into dst, as in ECB mode.
// It is faster than calling Encrypt on each block: four blocks go through the
// rounds side by side, which gives the processor four independent dependency
// chains. len(src) must be a multiple of 16 and dst at least as long; dst and
// src must overlap entirely or not at all.
func (c *serpentCipher) EncryptBlocks(dst, src []byte) {
	checkBlocks(dst, src)
	k := &c.rk
	for ; len(src) >= 4*BlockSize; src, dst = src[4*BlockSize:], dst[4*BlockSize:] {
		s, o := src[:64], dst[:64]
		a0 := binary.LittleEndian.Uint32(s[0:])
		b0 := binary.LittleEndian.Uint32(s[4:])
		d0 := binary.LittleEndian.Uint32(s[8:])
		e0 := binary.LittleEndian.Uint32(s[12:])
		a1 := binary.LittleEndian.Uint32(s[16:])
		b1 := binary.LittleEndian.Uint32(s[20:])
		d1 := binary.LittleEndian.Uint32(s[24:])
		e1 := binary.LittleEndian.Uint32(s[28:])
		a2 := binary.LittleEndian.Uint32(s[32:])
		b2 := binary.LittleEndian.Uint32(s[36:])
		d2 := binary.LittleEndian.Uint32(s[40:])
		e2 := binary.LittleEndian.Uint32(s[44:])
		a3 := binary.LittleEndian.Uint32(s[48:])
		b3 := binary.LittleEndian.Uint32(s[52:])
		d3 := binary.LittleEndian.Uint32(s[56:])
		e3 := binary.LittleEndian.Uint32(s[60:])
		for r := 0; r < rounds; r += 8 {
			kk := (*[32]uint32)(k[4*r:])
			a0, b0, d0, e0 = sboxE0(a0^kk[0], b0^kk[1], d0^kk[2], e0^kk[3])
			a1, b1, d1, e1 = sboxE0(a1^kk[0], b1^kk[1], d1^kk[2], e1^kk[3])
			a2, b2, d2, e2 = sboxE0(a2^kk[0], b2^kk[1], d2^kk[2], e2^kk[3])
			a3, b3, d3, e3 = sboxE0(a3^kk[0], b3^kk[1], d3^kk[2], e3^kk[3])
			a0, b0, d0, e0 = lt(a0, b0, d0, e0)
			a1, b1, d1, e1 = lt(a1, b1, d1, e1)
			a2, b2, d2, e2 = lt(a2, b2, d2, e2)
			a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxE1(a0^kk[4], b0^kk[5], d0^kk[6], e0^kk[7])
			a1, b1, d1, e1 = sboxE1(a1^kk[4], b1^kk[5], d1^kk[6], e1^kk[7])
			a2, b2, d2, e2 = sboxE1(a2^kk[4], b2^kk[5], d2^kk[6], e2^kk[7])
			a3, b3, d3, e3 = sboxE1(a3^kk[4], b3^kk[5], d3^kk[6], e3^kk[7])
			a0, b0, d0, e0 = lt(a0, b0, d0, e0)
			a1, b1, d1, e1 = lt(a1, b1, d1, e1)
			a2, b2, d2, e2 = lt(a2, b2, d2, e2)
			a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxE2(a0^kk[8], b0^kk[9], d0^kk[10], e0^kk[11])
			a1, b1, d1, e1 = sboxE2(a1^kk[8], b1^kk[9], d1^kk[10], e1^kk[11])
			a2, b2, d2, e2 = sboxE2(a2^kk[8], b2^kk[9], d2^kk[10], e2^kk[11])
			a3, b3, d3, e3 = sboxE2(a3^kk[8], b3^kk[9], d3^kk[10], e3^kk[11])
			a0, b0, d0, e0 = lt(a0, b0, d0, e0)
			a1, b1, d1, e1 = lt(a1, b1, d1, e1)
			a2, b2, d2, e2 = lt(a2, b2, d2, e2)
			a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxE3(a0^kk[12], b0^kk[13], d0^kk[14], e0^kk[15])
			a1, b1, d1, e1 = sboxE3(a1^kk[12], b1^kk[13], d1^kk[14], e1^kk[15])
			a2, b2, d2, e2 = sboxE3(a2^kk[12], b2^kk[13], d2^kk[14], e2^kk[15])
			a3, b3, d3, e3 = sboxE3(a3^kk[12], b3^kk[13], d3^kk[14], e3^kk[15])
			a0, b0, d0, e0 = lt(a0, b0, d0, e0)
			a1, b1, d1, e1 = lt(a1, b1, d1, e1)
			a2, b2, d2, e2 = lt(a2, b2, d2, e2)
			a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxE4(a0^kk[16], b0^kk[17], d0^kk[18], e0^kk[19])
			a1, b1, d1, e1 = sboxE4(a1^kk[16], b1^kk[17], d1^kk[18], e1^kk[19])
			a2, b2, d2, e2 = sboxE4(a2^kk[16], b2^kk[17], d2^kk[18], e2^kk[19])
			a3, b3, d3, e3 = sboxE4(a3^kk[16], b3^kk[17], d3^kk[18], e3^kk[19])
			a0, b0, d0, e0 = lt(a0, b0, d0, e0)
			a1, b1, d1, e1 = lt(a1, b1, d1, e1)
			a2, b2, d2, e2 = lt(a2, b2, d2, e2)
			a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxE5(a0^kk[20], b0^kk[21], d0^kk[22], e0^kk[23])
			a1, b1, d1, e1 = sboxE5(a1^kk[20], b1^kk[21], d1^kk[22], e1^kk[23])
			a2, b2, d2, e2 = sboxE5(a2^kk[20], b2^kk[21], d2^kk[22], e2^kk[23])
			a3, b3, d3, e3 = sboxE5(a3^kk[20], b3^kk[21], d3^kk[22], e3^kk[23])
			a0, b0, d0, e0 = lt(a0, b0, d0, e0)
			a1, b1, d1, e1 = lt(a1, b1, d1, e1)
			a2, b2, d2, e2 = lt(a2, b2, d2, e2)
			a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxE6(a0^kk[24], b0^kk[25], d0^kk[26], e0^kk[27])
			a1, b1, d1, e1 = sboxE6(a1^kk[24], b1^kk[25], d1^kk[26], e1^kk[27])
			a2, b2, d2, e2 = sboxE6(a2^kk[24], b2^kk[25], d2^kk[26], e2^kk[27])
			a3, b3, d3, e3 = sboxE6(a3^kk[24], b3^kk[25], d3^kk[26], e3^kk[27])
			a0, b0, d0, e0 = lt(a0, b0, d0, e0)
			a1, b1, d1, e1 = lt(a1, b1, d1, e1)
			a2, b2, d2, e2 = lt(a2, b2, d2, e2)
			a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxE7(a0^kk[28], b0^kk[29], d0^kk[30], e0^kk[31])
			a1, b1, d1, e1 = sboxE7(a1^kk[28], b1^kk[29], d1^kk[30], e1^kk[31])
			a2, b2, d2, e2 = sboxE7(a2^kk[28], b2^kk[29], d2^kk[30], e2^kk[31])
			a3, b3, d3, e3 = sboxE7(a3^kk[28], b3^kk[29], d3^kk[30], e3^kk[31])
			if r+8 < rounds {
				a0, b0, d0, e0 = lt(a0, b0, d0, e0)
				a1, b1, d1, e1 = lt(a1, b1, d1, e1)
				a2, b2, d2, e2 = lt(a2, b2, d2, e2)
				a3, b3, d3, e3 = lt(a3, b3, d3, e3)
			}
		}
		a0, b0, d0, e0 = a0^k[128], b0^k[129], d0^k[130], e0^k[131]
		a1, b1, d1, e1 = a1^k[128], b1^k[129], d1^k[130], e1^k[131]
		a2, b2, d2, e2 = a2^k[128], b2^k[129], d2^k[130], e2^k[131]
		a3, b3, d3, e3 = a3^k[128], b3^k[129], d3^k[130], e3^k[131]
		binary.LittleEndian.PutUint32(o[0:], a0)
		binary.LittleEndian.PutUint32(o[4:], b0)
		binary.LittleEndian.PutUint32(o[8:], d0)
		binary.LittleEndian.PutUint32(o[12:], e0)
		binary.LittleEndian.PutUint32(o[16:], a1)
		binary.LittleEndian.PutUint32(o[20:], b1)
		binary.LittleEndian.PutUint32(o[24:], d1)
		binary.LittleEndian.PutUint32(o[28:], e1)
		binary.LittleEndian.PutUint32(o[32:], a2)
		binary.LittleEndian.PutUint32(o[36:], b2)
		binary.LittleEndian.PutUint32(o[40:], d2)
		binary.LittleEndian.PutUint32(o[44:], e2)
		binary.LittleEndian.PutUint32(o[48:], a3)
		binary.LittleEndian.PutUint32(o[52:], b3)
		binary.LittleEndian.PutUint32(o[56:], d3)
		binary.LittleEndian.PutUint32(o[60:], e3)
	}
	for ; len(src) > 0; src, dst = src[BlockSize:], dst[BlockSize:] {
		c.Encrypt(dst, src)
	}
}

// DecryptBlocks is EncryptBlocks for decryption.
func (c *serpentCipher) DecryptBlocks(dst, src []byte) {
	checkBlocks(dst, src)
	k := &c.rk
	for ; len(src) >= 4*BlockSize; src, dst = src[4*BlockSize:], dst[4*BlockSize:] {
		s, o := src[:64], dst[:64]
		a0 := binary.LittleEndian.Uint32(s[0:])
		b0 := binary.LittleEndian.Uint32(s[4:])
		d0 := binary.LittleEndian.Uint32(s[8:])
		e0 := binary.LittleEndian.Uint32(s[12:])
		a1 := binary.LittleEndian.Uint32(s[16:])
		b1 := binary.LittleEndian.Uint32(s[20:])
		d1 := binary.LittleEndian.Uint32(s[24:])
		e1 := binary.LittleEndian.Uint32(s[28:])
		a2 := binary.LittleEndian.Uint32(s[32:])
		b2 := binary.LittleEndian.Uint32(s[36:])
		d2 := binary.LittleEndian.Uint32(s[40:])
		e2 := binary.LittleEndian.Uint32(s[44:])
		a3 := binary.LittleEndian.Uint32(s[48:])
		b3 := binary.LittleEndian.Uint32(s[52:])
		d3 := binary.LittleEndian.Uint32(s[56:])
		e3 := binary.LittleEndian.Uint32(s[60:])
		a0, b0, d0, e0 = a0^k[128], b0^k[129], d0^k[130], e0^k[131]
		a1, b1, d1, e1 = a1^k[128], b1^k[129], d1^k[130], e1^k[131]
		a2, b2, d2, e2 = a2^k[128], b2^k[129], d2^k[130], e2^k[131]
		a3, b3, d3, e3 = a3^k[128], b3^k[129], d3^k[130], e3^k[131]
		for r := rounds; r > 0; r -= 8 {
			kk := (*[32]uint32)(k[4*r-32:])
			a0, b0, d0, e0 = sboxD7(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD7(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD7(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD7(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[28], b0^kk[29], d0^kk[30], e0^kk[31]
			a1, b1, d1, e1 = a1^kk[28], b1^kk[29], d1^kk[30], e1^kk[31]
			a2, b2, d2, e2 = a2^kk[28], b2^kk[29], d2^kk[30], e2^kk[31]
			a3, b3, d3, e3 = a3^kk[28], b3^kk[29], d3^kk[30], e3^kk[31]
			a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
			a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
			a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
			a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxD6(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD6(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD6(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD6(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[24], b0^kk[25], d0^kk[26], e0^kk[27]
			a1, b1, d1, e1 = a1^kk[24], b1^kk[25], d1^kk[26], e1^kk[27]
			a2, b2, d2, e2 = a2^kk[24], b2^kk[25], d2^kk[26], e2^kk[27]
			a3, b3, d3, e3 = a3^kk[24], b3^kk[25], d3^kk[26], e3^kk[27]
			a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
			a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
			a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
			a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxD5(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD5(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD5(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD5(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[20], b0^kk[21], d0^kk[22], e0^kk[23]
			a1, b1, d1, e1 = a1^kk[20], b1^kk[21], d1^kk[22], e1^kk[23]
			a2, b2, d2, e2 = a2^kk[20], b2^kk[21], d2^kk[22], e2^kk[23]
			a3, b3, d3, e3 = a3^kk[20], b3^kk[21], d3^kk[22], e3^kk[23]
			a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
			a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
			a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
			a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxD4(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD4(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD4(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD4(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[16], b0^kk[17], d0^kk[18], e0^kk[19]
			a1, b1, d1, e1 = a1^kk[16], b1^kk[17], d1^kk[18], e1^kk[19]
			a2, b2, d2, e2 = a2^kk[16], b2^kk[17], d2^kk[18], e2^kk[19]
			a3, b3, d3, e3 = a3^kk[16], b3^kk[17], d3^kk[18], e3^kk[19]
			a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
			a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
			a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
			a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxD3(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD3(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD3(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD3(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[12], b0^kk[13], d0^kk[14], e0^kk[15]
			a1, b1, d1, e1 = a1^kk[12], b1^kk[13], d1^kk[14], e1^kk[15]
			a2, b2, d2, e2 = a2^kk[12], b2^kk[13], d2^kk[14], e2^kk[15]
			a3, b3, d3, e3 = a3^kk[12], b3^kk[13], d3^kk[14], e3^kk[15]
			a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
			a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
			a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
			a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxD2(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD2(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD2(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD2(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[8], b0^kk[9], d0^kk[10], e0^kk[11]
			a1, b1, d1, e1 = a1^kk[8], b1^kk[9], d1^kk[10], e1^kk[11]
			a2, b2, d2, e2 = a2^kk[8], b2^kk[9], d2^kk[10], e2^kk[11]
			a3, b3, d3, e3 = a3^kk[8], b3^kk[9], d3^kk[10], e3^kk[11]
			a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
			a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
			a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
			a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxD1(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD1(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD1(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD1(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[4], b0^kk[5], d0^kk[6], e0^kk[7]
			a1, b1, d1, e1 = a1^kk[4], b1^kk[5], d1^kk[6], e1^kk[7]
			a2, b2, d2, e2 = a2^kk[4], b2^kk[5], d2^kk[6], e2^kk[7]
			a3, b3, d3, e3 = a3^kk[4], b3^kk[5], d3^kk[6], e3^kk[7]
			a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
			a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
			a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
			a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			a0, b0, d0, e0 = sboxD0(a0, b0, d0, e0)
			a1, b1, d1, e1 = sboxD0(a1, b1, d1, e1)
			a2, b2, d2, e2 = sboxD0(a2, b2, d2, e2)
			a3, b3, d3, e3 = sboxD0(a3, b3, d3, e3)
			a0, b0, d0, e0 = a0^kk[0], b0^kk[1], d0^kk[2], e0^kk[3]
			a1, b1, d1, e1 = a1^kk[0], b1^kk[1], d1^kk[2], e1^kk[3]
			a2, b2, d2, e2 = a2^kk[0], b2^kk[1], d2^kk[2], e2^kk[3]
			a3, b3, d3, e3 = a3^kk[0], b3^kk[1], d3^kk[2], e3^kk[3]
			if r > 8 {
				a0, b0, d0, e0 = ilt(a0, b0, d0, e0)
				a1, b1, d1, e1 = ilt(a1, b1, d1, e1)
				a2, b2, d2, e2 = ilt(a2, b2, d2, e2)
				a3, b3, d3, e3 = ilt(a3, b3, d3, e3)
			}
		}
		binary.LittleEndian.PutUint32(o[0:], a0)
		binary.LittleEndian.PutUint32(o[4:], b0)
		binary.LittleEndian.PutUint32(o[8:], d0)
		binary.LittleEndian.PutUint32(o[12:], e0)
		binary.LittleEndian.PutUint32(o[16:], a1)
		binary.LittleEndian.PutUint32(o[20:], b1)
		binary.LittleEndian.PutUint32(o[24:], d1)
		binary.LittleEndian.PutUint32(o[28:], e1)
		binary.LittleEndian.PutUint32(o[32:], a2)
		binary.LittleEndian.PutUint32(o[36:], b2)
		binary.LittleEndian.PutUint32(o[40:], d2)
		binary.LittleEndian.PutUint32(o[44:], e2)
		binary.LittleEndian.PutUint32(o[48:], a3)
		binary.LittleEndian.PutUint32(o[52:], b3)
		binary.LittleEndian.PutUint32(o[56:], d3)
		binary.LittleEndian.PutUint32(o[60:], e3)
	}
	for ; len(src) > 0; src, dst = src[BlockSize:], dst[BlockSize:] {
		c.Decrypt(dst, src)
	}
}
