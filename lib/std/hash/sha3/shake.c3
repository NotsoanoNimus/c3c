// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
module std::hash::sha3::shake_internal { SECURITY_LEVEL, ROUNDS, DELIMITER } @private;

import std::hash::sha3::keccak;

const RATE = keccak::rate(SECURITY_LEVEL);

struct ShakeContext
{
	inline $typefrom(keccak::keccak($security_level: SECURITY_LEVEL, $rounds: ROUNDS, $delimiter: DELIMITER)) k;
	bool is_padded;
	usz offset;
	char[RATE] buf;
}

fn void ShakeContext.pad(&self) => unreachable("pad() must never be accessed directly");

fn void ShakeContext.squeeze(&self, char[] into)
{
	if (!self.is_padded)
	{
		self.k.pad();
		self.is_padded = true;
	}

	char[] out = into;
	if (self.offset > 0)
	{
		usz left = min(self.buf.len - self.offset, out.len);
		if (left > 0)
		{
			out[:left] = self.buf[self.offset:left];
			out = out[left..];
			self.offset += left;
			if (out.len == 0) return;
		}
	}

	char[] full_blocks = out[:(out.len - out.len % RATE)];
	if (full_blocks.len > 0)
	{
		self.k.squeeze(full_blocks[..]);
		out = out[full_blocks.len..];
	}
	if (out.len > 0)
	{
		self.k.squeeze(self.buf[..]);
		out[..] = self.buf[:out.len];
		self.offset = out.len;
	}
}


module std::hash::sha3::shake;

import std::hash::sha3::shake_internal @public;

macro typeid shake($security_level, $rounds = 24, $delimiter = 0x1F) @const
{
	return (ShakeContext { $security_level, $rounds, $delimiter }).typeid;
}

macro char[*] xof($security_level, $outlen_bytes, char[] data, char delimiter_override = 0x1F) @local
{
	char[$outlen_bytes] into;

	$typefrom(shake($security_level)) s;
	defer s.wipe();
	s.init(delimiter_override);
	s.update(data);
	s.final(into[..]);

	return into;
}

alias Shake128 = $typefrom(shake(128));
alias Shake256 = $typefrom(shake(256));

macro char[*] xof_128($outlen_bytes, char[] data) => xof(128, $outlen_bytes, data) @inline;
macro char[*] xof_256($outlen_bytes, char[] data) => xof(256, $outlen_bytes, data) @inline;
