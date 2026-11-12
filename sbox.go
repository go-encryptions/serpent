package serpent

// The bitsliced S-box expressions below were discovered by Dag Arne Osvik
// ("Speeding Up Serpent") and are the ones used by Botan's
// src/lib/block/serpent/serpent_sbox.h (BSD-2-Clause, Jack Lloyd). Each
// function maps four words (bit 0 of every S-box input in a, bit 1 in b, ...)
// to four words. Go's ^x is C's ~x.

func sboxE0(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	d ^= a
	t0 := b
	b &= d
	t0 ^= c
	b ^= a
	a |= d
	a ^= t0
	t0 ^= d
	d ^= c
	c |= b
	c ^= t0
	t0 = ^t0
	t0 |= b
	b ^= d
	b ^= t0
	d |= a
	b ^= d
	t0 ^= d
	d = a
	a = b
	b = t0
	return a, b, c, d
}

func sboxE1(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a = ^a
	c = ^c
	t0 := a
	a &= b
	c ^= a
	a |= d
	d ^= c
	b ^= a
	a ^= t0
	t0 |= b
	b ^= d
	c |= a
	c &= t0
	a ^= b
	b &= c
	b ^= a
	a &= c
	t0 ^= a
	a = c
	c = d
	d = b
	b = t0
	return a, b, c, d
}

func sboxE2(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	t0 := a
	a &= c
	a ^= d
	c ^= b
	c ^= a
	d |= t0
	d ^= b
	t0 ^= c
	b = d
	d |= t0
	d ^= a
	a &= b
	t0 ^= a
	b ^= d
	b ^= t0
	a = c
	c = b
	b = d
	d = ^t0
	return a, b, c, d
}

func sboxE3(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	t0 := a
	a |= d
	d ^= b
	b &= t0
	t0 ^= c
	c ^= d
	d &= a
	t0 |= b
	d ^= t0
	a ^= b
	t0 &= a
	b ^= d
	t0 ^= c
	b |= a
	b ^= c
	a ^= d
	c = b
	b |= d
	a ^= b
	b = c
	c = d
	d = t0
	return a, b, c, d
}

func sboxE4(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	b ^= d
	d = ^d
	c ^= d
	d ^= a
	t0 := b
	b &= d
	b ^= c
	t0 ^= d
	a ^= t0
	c &= t0
	c ^= a
	a &= b
	d ^= a
	t0 |= b
	t0 ^= a
	a |= d
	a ^= c
	c &= d
	a = ^a
	t0 ^= c
	c = a
	a = b
	b = t0
	return a, b, c, d
}

func sboxE5(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a ^= b
	b ^= d
	d = ^d
	t0 := b
	b &= a
	c ^= d
	b ^= c
	c |= t0
	t0 ^= d
	d &= b
	d ^= a
	t0 ^= b
	t0 ^= c
	c ^= a
	a &= d
	c = ^c
	a ^= t0
	t0 |= d
	t0 ^= c
	c = a
	a = b
	b = d
	d = t0
	return a, b, c, d
}

func sboxE6(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	c = ^c
	t0 := d
	d &= a
	a ^= t0
	d ^= c
	c |= t0
	b ^= d
	c ^= a
	a |= b
	c ^= b
	t0 ^= a
	a |= d
	a ^= c
	t0 ^= d
	t0 ^= a
	d = ^d
	c &= t0
	d ^= c
	c = t0
	return a, b, c, d
}

func sboxE7(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	t0 := b
	b |= c
	b ^= d
	t0 ^= c
	c ^= b
	d |= t0
	d &= a
	t0 ^= c
	d ^= b
	b |= t0
	b ^= a
	a |= t0
	a ^= c
	b ^= t0
	c ^= b
	b &= a
	b ^= t0
	c = ^c
	c |= a
	t0 ^= c
	c = b
	b = d
	d = a
	a = t0
	return a, b, c, d
}

func sboxD0(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	c = ^c
	t0 := b
	b |= a
	t0 = ^t0
	b ^= c
	c |= t0
	b ^= d
	a ^= t0
	c ^= a
	a &= d
	t0 ^= a
	a |= b
	a ^= c
	d ^= t0
	c ^= b
	d ^= a
	d ^= b
	c &= d
	t0 ^= c
	c = b
	b = t0
	return a, b, c, d
}

func sboxD1(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	t0 := b
	b ^= d
	d &= b
	t0 ^= c
	d ^= a
	a |= b
	c ^= d
	a ^= t0
	a |= c
	b ^= d
	a ^= b
	b |= d
	b ^= a
	t0 = ^t0
	t0 ^= b
	b |= a
	b ^= a
	b |= t0
	d ^= b
	b = a
	a = t0
	t0 = c
	c = d
	d = t0
	return a, b, c, d
}

func sboxD2(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	c ^= d
	d ^= a
	t0 := d
	d &= c
	d ^= b
	b |= c
	b ^= t0
	t0 &= d
	c ^= d
	t0 &= a
	t0 ^= c
	c &= b
	c |= a
	d = ^d
	c ^= d
	a ^= d
	a &= b
	d ^= t0
	d ^= a
	a = b
	b = t0
	return a, b, c, d
}

func sboxD3(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	t0 := c
	c ^= b
	a ^= c
	t0 &= c
	t0 ^= a
	a &= b
	b ^= d
	d |= t0
	c ^= d
	a ^= d
	b ^= t0
	d &= c
	d ^= b
	b ^= a
	b |= c
	a ^= d
	b ^= t0
	a ^= b
	t0 = a
	a = c
	c = d
	d = t0
	return a, b, c, d
}

func sboxD4(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	t0 := c
	c &= d
	c ^= b
	b |= d
	b &= a
	t0 ^= c
	t0 ^= b
	b &= c
	a = ^a
	d ^= t0
	b ^= d
	d &= a
	d ^= c
	a ^= b
	c &= a
	d ^= a
	c ^= t0
	c |= d
	d ^= a
	c ^= b
	b = d
	d = t0
	return a, b, c, d
}

func sboxD5(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	b = ^b
	t0 := d
	c ^= b
	d |= a
	d ^= c
	c |= b
	c &= a
	t0 ^= d
	c ^= t0
	t0 |= a
	t0 ^= b
	b &= c
	b ^= d
	t0 ^= c
	d &= t0
	t0 ^= b
	d ^= t0
	t0 = ^t0
	d ^= a
	// The output words are permuted: (a, b, c, d) = (b, t0, d, c). Returning
	// them directly keeps the function under the inlining budget, which the
	// four-block loops need so that no call spills their sixteen state words.
	return b, t0, d, c
}

func sboxD6(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a ^= c
	t0 := c
	c &= a
	t0 ^= d
	c = ^c
	d ^= b
	c ^= d
	t0 |= a
	a ^= c
	d ^= t0
	t0 ^= b
	b &= d
	b ^= a
	a ^= d
	a |= c
	d ^= b
	t0 ^= a
	a = b
	b = c
	c = t0
	return a, b, c, d
}

func sboxD7(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	t0 := c
	c ^= a
	a &= d
	t0 |= d
	c = ^c
	d ^= b
	b |= a
	a ^= c
	c &= t0
	d &= t0
	b ^= c
	c ^= a
	a |= c
	t0 ^= b
	a ^= d
	d ^= t0
	t0 |= a
	d ^= c
	t0 ^= c
	c = b
	b = a
	a = d
	d = t0
	return a, b, c, d
}
