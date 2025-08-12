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
module std::hash::keccak::keccak_internal { F, OUTPUT_BITS, ROUNDS, DELIMITER } @private;

import std::math;


const CAPACITY = OUTPUT_BITS * 2;
const BLOCK_BYTES = F / 8;
const MAX_ROUNDS = 12 + 2 * math::@intlog2(F / 25);
const RATE = BLOCK_BYTES - CAPACITY / 8;
const SPONGE_WORDS = F / 8 / ulong.sizeof;


const ulong[24] RC = {   // round constants
	0x0000_0000_0000_0001,  0x0000_0000_0000_8082,  0x8000_0000_0000_808a,  0x8000_0000_8000_8000,
	0x0000_0000_0000_808b,  0x0000_0000_8000_0001,  0x8000_0000_8000_8081,  0x8000_0000_0000_8009,
	0x0000_0000_0000_008a,  0x0000_0000_0000_0088,  0x0000_0000_8000_8009,  0x0000_0000_8000_000a,
	0x0000_0000_8000_808b,  0x8000_0000_0000_008b,  0x8000_0000_0000_8089,  0x8000_0000_0000_8003,
	0x8000_0000_0000_8002,  0x8000_0000_0000_0080,  0x0000_0000_0000_800a,  0x8000_0000_8000_000a,
	0x8000_0000_8000_8081,  0x8000_0000_0000_8080,  0x0000_0000_8000_0001,  0x8000_0000_8000_8008,
};

macro @rc($round) @const => RC[$round];

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
	char runtime_delimiter;
}


// The delimiter value can be given at compile-time, but can also be overridden at runtime
//   by certain hash suites (e.g. TurboSHAKE).
fn void KeccakContext.init(&self, char runtime_delimiter = DELIMITER) @inline
	=> *self = { .runtime_delimiter = runtime_delimiter };


fn void KeccakContext.update(&self, char[] data) => self.absorb(data);


fn char[OUTPUT_BITS / 8] KeccakContext.final(&self)
{
	char[OUTPUT_BITS / 8] result;

	self.pad();
	self.squeeze(result[:(OUTPUT_BITS / 8)]);

	defer self.wipe();

	return result;
}


fn char[OUTPUT_BITS / 8] hash(char[] data)
{
    KeccakContext k @noinit;
    k.init();
    k.update(data);
    return k.final();
}


fn void KeccakContext.wipe(&self) @inline @if(env::LIBC) => mem::zero_volatile(@as_char_view(*self));
fn void KeccakContext.wipe(&self) @inline @if(!env::LIBC)
{
	for (usz i = 0; i < $sizeof(self); ++i) *@unaligned_load(&((char*)self)[i], 1) = 0x00;
}


fn void KeccakContext.fill_block(&self) @inline
{
	foreach(j, c : self.buf[:self.offset]) self.state_bytes[j] ^= c;

	self.@permute_r(ROUNDS);
	self.offset = 0;
}


fn void KeccakContext.absorb(&self, char[] input) @inline
{
	usz i;

	if (self.offset > 0)   // handle any leftovers
	{
		usz left = min(RATE - self.offset, input.len);

		self.buf[self.offset:left] = input[:left];
		self.offset += left;

		if (left == input.len) return;   // awaiting more input before running rounds

		if (self.offset == RATE)
		{
			foreach (j, c : self.buf) self.state_bytes[j] ^= c;

			self.@permute_r(ROUNDS);
			self.offset = 0;
		}

		i = left;
	}

	for (; i + RATE < input.len; i += RATE)
	{
		foreach (j, c : input[i:RATE]) self.state_bytes[j] ^= c;

		self.@permute_r(ROUNDS);
	}

	usz left = input.len - i;
	if (left > 0) self.buf[:left] = input[i:left];

	self.offset = left;
}


fn void KeccakContext.pad(&self) @inline
{
	foreach (j, c : self.buf[:self.offset]) self.state_bytes[j] ^= c;

	if (self.offset == RATE)
	{
		self.@permute_r(ROUNDS);
		self.offset = 0;
	}

	self.state_bytes[self.offset] ^= self.runtime_delimiter;
	self.state_bytes[RATE - 1] ^= 0x80;

	self.@permute_r(ROUNDS);
	self.offset = 0;
}


fn void KeccakContext.squeeze(&self, char[] out) @inline
{
	usz i;

	if (self.offset == RATE)
	{
		self.@permute_r(ROUNDS);
	}
	else if (@unlikely(self.offset > 0))
	{
		char[RATE] localbuf;
		localbuf[..] = self.buf[..];

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

	for (; i + RATE < out.len; i += RATE)
	{
		out[i:RATE] = self.state_bytes[:RATE];

		self.@permute_r(ROUNDS);
	}

	usz left = out.len - i;
	if (left > 0) out[i:left] = self.state_bytes[:left];

	self.offset = left;
}


macro KeccakContext.@permute(&self) => self.@permute_r(MAX_ROUNDS);


macro KeccakContext.@permute_r(&self, $rounds) => self.permute_r($rounds);

fn void KeccakContext.permute_r(&self, usz rounds)
{
	usz i = RC.len - rounds;

	for (; i < RC.len - (RC.len % 3); i += 3)
	{
		self.round(RC[i + 0]);
		self.round(RC[i + 1]);
		self.round(RC[i + 2]);
	}

	for (; i < RC.len; ++i) self.round(RC[i]);
}


macro KeccakContext.@round(&self, $round_counter) => self.round(@rc($round_counter));

fn void KeccakContext.round(&self, usz rc)
{
	ulong[5] b;
	ulong t;

	// theta
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

	// rho and pi
	$for var $x = 0; $x < 24; ++$x:
		b[0] = self.state[PI[$x]];
		self.state[PI[$x]] = t.rotl(RHO[$x]);
		t = b[0];
	$endfor

	// chi
	$for var $y = 0; $y < 25; $y += 5:
		$for var $x = 0; $x < 5; ++$x:
			b[$x] = self.state[$y + $x];
		$endfor
		$for var $x = 0; $x < 5; ++$x:
			self.state[$y + $x] ^= (~b[($x + 1) % 5]) & b[($x + 2) % 5];
		$endfor
	$endfor

	// iota
	self.state[0] ^= rc;
}


// Declare Keccak-specific hashing contexts and methods.
module std::hash::keccak::keccak;

import std::hash::keccak::keccak_internal @public;

alias Keccak224 = KeccakContext { 1600, 224, 24, 0x01 };
alias hash_224 = keccak_internal::hash { 1600, 224, 24, 0x01 };

alias Keccak256 = KeccakContext { 1600, 256, 24, 0x01 };
alias hash_256 = keccak_internal::hash { 1600, 256, 24, 0x01 };

alias Keccak384 = KeccakContext { 1600, 384, 24, 0x01 };
alias hash_384 = keccak_internal::hash { 1600, 384, 24, 0x01 };

alias Keccak512 = KeccakContext { 1600, 512, 24, 0x01 };
alias hash_512 = keccak_internal::hash { 1600, 512, 24, 0x01 };
