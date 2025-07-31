// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
<*
@require values::@is_int(F) : `F must be an integer type.`
@require values::@is_int(OUTPUT_BITS) : `OUTPUT_BITS must be an integer type.`
@require values::@is_int(ROUNDS) : `ROUNDS must be an integer type.`
@require values::@is_int(DELIMITER) : `DELIMITER must be an integer type less than 256.`

@require F >= 200 &&& F <= 1600 : `Invalid Keccak F; out of range.`
@require F % 200 == 0 : `Keccak F must be a multiple of 200.`
@require OUTPUT_BITS > 0 &&& OUTPUT_BITS * 2 < F &&& OUTPUT_BITS % 8 == 0 : `Invalid output bit length. Must be a multiple of 8, less than (F/2), and non-zero.`
@require ROUNDS <= MAX_ROUNDS : `Keccak Rounds must be less than or equal to the maximum value derived from F.`
@require DELIMITER <= 0xFF : `Keccak Delimiters can only be one byte wide (< 255).`
*>
module std::hash::keccak { F, OUTPUT_BITS, ROUNDS, DELIMITER } @private;

import std::math;


const CAPACITY = OUTPUT_BITS * 2;
const BLOCK_BYTES = F / 8;
const MAX_ROUNDS = 12 + 2 * math::log2(F / 25);
const RATE = BLOCK_BYTES - CAPACITY / 8;
const SPONGE_WORDS = F / 8 / ulong.sizeof;


const ulong[24] RC = {   // round constants
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

const char[24] RHO = {
	1,  3,   6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44
};

const char[24] PI = {
	10,  7, 11, 17, 18, 3,
	 5, 16,  8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22,  9,  6, 1
};


struct KeccakContext
{
	union   // keccak state
	{
		ulong[SPONGE_WORDS] state;
		char[SPONGE_WORDS * ulong.sizeof] state_bytes;
	}
	usz offset;   // tracking leftover bytes from absorption
	char[RATE] buf;   // absorption buffer
}


fn void KeccakContext.init(&self, usz f = 1600) @inline => *self = {};


fn void KeccakContext.update(&self, char[] data) @inline => self.absorb(data);


fn void KeccakContext.absorb(&self, char[] input)
{
	usz i = input.len;

	if (self.offset > 0)   // handle any leftovers
	{
		usz left = min(RATE - self.offset, input.len);

		self.buf[self.offset:left] = input[:left];
		self.offset += left;

		if (left == input.len) return;   // awaiting more input before running rounds

		if (self.offset == RATE)
		{
			self.state[:RATE] ^= self.buf[..];
			self.@permute_r(ROUNDS);
			self.offset = 0;
		}

		i = left;
	}

	for (; i >= RATE; i -= RATE)
	{
		self.state[:RATE] ^= input[(input.len - i):RATE];
		self.@permute_r(ROUNDS);
	}

	if (i > 0) self.buf[..i] = input[^i..];

	self.offset = i;
}


fn char[OUTPUT_BITS / 8] KeccakContext.final(&self)
{
	char[OUTPUT_BITS / 8] result;

	self.pad();
	self.squeeze(result[:(OUTPUT_BITS / 8)]);

	return result;
}


fn void KeccakContext.pad(&self)
{
	self.state[:self.offset] ^= self.buf[:self.offset];

	if (self.offset == RATE)
	{
		self.@permute_r(ROUNDS);
		self.offset = 0;
	}

	self.state[self.offset] ^= DELIMITER;
	self.state[RATE - 1] ^= 0x80;

	self.@permute_r(ROUNDS);
	self.offset = 0;
}


fn void KeccakContext.squeeze(&self, char[] out)
{
	usz i = out.len;

	if (self.offset == RATE)
	{
		self.@permute_r(ROUNDS);
	}
	else if (@unlikely(self.offset > 0))
	{
		char[RATE] localbuf;
		localbuf[..] = self.state[..];

		usz left = min(RATE - self.offset, out.len);

		out[:left] = localbuf[self.offset:left];
		self.offset += left;

		if (left == out.len) return;   // awaiting more data

		if (self.offset == RATE)
		{
			self.offset = 0;
			self.@permute_r(ROUNDS);
		}

		i = left;
	}

	for (; i >= RATE; i -= RATE)
	{
		out[(out.len - i):RATE] = self.state[:RATE];
		self.@permute_r(ROUNDS);
	}

	if (i > 0) out[^i..] = self.state[^i..];

	self.offset = i;
}


macro KeccakContext.@permute(&self) => self.@permute_r(MAX_ROUNDS);


macro KeccakContext.@permute_r(&self, $rounds)
{
	var $i = RC.len - $rounds;

	$for ; $i < RC.len - (RC.len % 3); $i += 3:
		self.@round($i);
		self.@round($i + 1);
		self.@round($i + 2);
	$endfor

	$for ; $i < RC.len; ++$i:
		self.@round($i);
	$endfor
}


macro KeccakContext.@round(&self, $round_counter)
{
	ulong[5] b;
	ulong t;

	// Theta function.
	$for var $x = 0; $x < 5; ++$x:
		b[$x] = 0;
		$for var $y = 0; $y < 25; $y += 5:
			b[$x] ^= self.state[$x + $y];
		$endfor
	$endfor
	$for var $x = 0; $x < 5; ++$x:
		$for var $y = 0; $y < 25; $y += 5:
			self.state[$x + $y] ^= b[($x + 4) % 5] ^ b[($x + 1) % 5].rotl(1);
		$endfor
	$endfor

	// Rho and Pi functions.
	t = self.state[1];
	$for var $x = 0; $x < 24; ++$x:
		b[0] = self.state[PI[$x]];
		self.state[PI[$x]] = t.rotl(RHO[$x]);
		t = b[0];
	$endfor

	// Chi function.
	$for var $y = 0; $y < 25; $y += 5:
		$for var $x = 0; $x < 5; ++$x:
			b[$x] = self.state[$y + $x];
		$endfor
		$for var $x = 0; $x < 5; ++$x:
			// self.state[$y + $x] = b[$x] ^ ((~b[($x + 1) % 5]) & b[($x + 2) % 5]);
			self.state[$y + $x] ^= (~b[($x + 1) % 5]) & b[($x + 2) % 5];
		$endfor
	$endfor

	// Iota function.
	self.state[0] ^= RC[$round_counter];
}
