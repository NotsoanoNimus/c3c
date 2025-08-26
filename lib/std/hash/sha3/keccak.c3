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
module std::hash::sha3::keccak_internal { F, OUTPUT_BITS, ROUNDS, DELIMITER } @private;

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
	bool is_padded;
}


// The delimiter value can be given at compile-time, but can also be overridden at runtime
//   by certain hash suites (e.g. TurboSHAKE).
fn void KeccakContext.init(&self, char runtime_delimiter = DELIMITER) @inline
	=> *self = { .runtime_delimiter = runtime_delimiter };


fn void KeccakContext.update(&self, char[] data) => self.absorb(data) @inline;


fn void KeccakContext.final(&self, char[] into)
{
	defer self.wipe();
	if (!self.is_padded) self.pad();
	self.squeeze(into);
}

fn void hash_into(char[] data, char[] into)
{
	KeccakContext k @noinit;
	defer k.wipe();
	k.init();
	k.update(data);
	k.final(into);
}


fn void KeccakContext.wipe(&self) @inline => mem::zero_volatile(@as_char_view(*self));


fn void KeccakContext.fill_block(&self) @inline
{
	foreach(j, c : self.buf[:self.offset]) self.state_bytes[j] ^= c;

	self.permute_r(ROUNDS);
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

			self.permute_r(ROUNDS);
			self.offset = 0;
		}

		i = left;
	}

	for (; i + RATE < input.len; i += RATE)
	{
		foreach (j, c : input[i:RATE]) self.state_bytes[j] ^= c;

		self.permute_r(ROUNDS);
	}

	usz left = input.len - i;
	if (left > 0) self.buf[:left] = input[i:left];

	self.offset = left;
}


fn void KeccakContext.pad(&self) @private @inline
{
	foreach (j, c : self.buf[:self.offset]) self.state_bytes[j] ^= c;

	if (self.offset == RATE)
	{
		self.permute_r(ROUNDS);
		self.offset = 0;
	}

	self.state_bytes[self.offset] ^= self.runtime_delimiter;
	self.state_bytes[RATE - 1] ^= 0x80;

	self.permute_r(ROUNDS);
	self.offset = 0;

	self.is_padded = true;
}


fn void KeccakContext.squeeze(&self, char[] out) @inline
{
	usz i;

	if (self.offset == RATE)
	{
		self.permute_r(ROUNDS);
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

			self.permute_r(ROUNDS);
		}

		i = left;
	}

	for (; i + RATE < out.len; i += RATE)
	{
		out[i:RATE] = self.state_bytes[:RATE];

		self.permute_r(ROUNDS);
	}

	usz left = out.len - i;
	if (left > 0) out[i:left] = self.state_bytes[:left];

	self.offset = left;
}


fn void KeccakContext.permute_r(&self, usz rounds) @local
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


fn void KeccakContext.round(&self, ulong rc) @local
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
	t = self.state[1];
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
module std::hash::sha3::keccak;

import std::hash::sha3::keccak_internal @public;

macro rate($security_level, $f = 1600) @const => ($f - ($security_level * 2)) / 8;

macro typeid keccak($security_level, $rounds = 24, $delimiter = 0x01, $f = 1600) @const
{
	return (KeccakContext { $f, $security_level, $rounds, $delimiter }).typeid;
}

macro char[*] hash($security_level, char[] data) @local
{
	char[$security_level / 8] result;
	keccak_internal::hash_into { 1600, $security_level, 24, 0x01 }(data, result[..]);
	return result;
}

macro char[*] explicit_hash($security_level, $delimiter, $outlen_bytes, char[] data, $f = 1600, $rounds = 24)
{
	char[$outlen_bytes] result;
	keccak_internal::hash_into { $f, $security_level, $rounds, $delimiter }(data, result[..]);
	return result[..];
}

alias Keccak224 = $typefrom(keccak(224));
alias Keccak256 = $typefrom(keccak(256));
alias Keccak384 = $typefrom(keccak(384));
alias Keccak512 = $typefrom(keccak(512));

fn char[224/8] hash_224(char[] data) => hash(224, data) @inline;
fn char[256/8] hash_256(char[] data) => hash(256, data) @inline;
fn char[384/8] hash_384(char[] data) => hash(384, data) @inline;
fn char[512/8] hash_512(char[] data) => hash(512, data) @inline;
