// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// See: NIST SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//
<*
 @require types::is_int($typeof(SECURITY_LEVEL)) &&& SECURITY_LEVEL > 0 : "SECURITY_LEVEL must be a positive integer value greater than 0."
*>
module std::hash::sha3::kmac_internal { SECURITY_LEVEL } @private;

import std::hash::sha3::keccak;
import std::hash::sha3::cshake;
import std::hash::sha3::nist @public;

const RATE = keccak::rate(SECURITY_LEVEL);

struct KmacContext
{
	inline $typefrom(cshake::cshake(SECURITY_LEVEL)) c;
	bool is_xof_mode;
}

fn void KmacContext.init(&self, char[] key, String optional_customization = "", bool is_xof_mode = false)
{
	self.is_xof_mode = is_xof_mode;
	self.c.init(KMAC, optional_customization);

	self.c.update(nist::@ct_encode_length(NistEncodingType.LEFT, RATE / 8));

	self.c.update(nist::encode_length(NistEncodingType.LEFT, key.len));
	self.c.update(key);

	self.c.fill_block();
}

<*
 @require out.len > 0
*>
macro void KmacContext.final(&self, char[] out)
{
	if (self.is_xof_mode)
	{
		self.c.update(nist::@ct_encode_length(NistEncodingType.RIGHT, 0));
	}
	else
	{
		self.c.update(nist::encode_length(NistEncodingType.RIGHT, out.len));
	}

	self.c.final(out);
}

<*
 @require out.len > 0
*>
macro void KmacContext.squeeze(&self, char[] out)
{
	if (!self.c.is_padded)   // becomes 'true' after the first 'squeeze' call below
	{
		if (self.is_xof_mode)
		{
			self.c.update(nist::@ct_encode_length(NistEncodingType.RIGHT, 0));
		}
		else
		{
			self.c.update(nist::encode_length(NistEncodingType.RIGHT, out.len));
		}
	}

	self.c.squeeze(out);
}


// Names for the KMAC structures are a bit 
module std::hash::sha3::kmac;

import std::hash::sha3::kmac_internal @public;

macro typeid kmac($security_level) @local @const
{
	return (KmacContext { $security_level }).typeid;
}

macro char[*] xof($security_level, $outlen_bytes, char[] key, char[] data, String optional_customization = "", bool $is_xof = false) @local
{
	char [$outlen_bytes] result;

	$typefrom(kmac($security_level)) c;
	defer c.wipe();

	c.init(key, optional_customization, $is_xof);
	c.update(data);
	c.final(result[..]);

	return result;
}

alias Kmac128 = $typefrom(kmac(128));
alias Kmac256 = $typefrom(kmac(256));

struct KmacXOF128
{
	inline $typefrom(kmac(128)) k;
}
fn void KmacXOF128.init(&self, char[] key, String optional_customization = "") => self.k.init(key, optional_customization, is_xof_mode: true) @inline;

struct KmacXOF256
{
	inline $typefrom(kmac(256)) k;
}
fn void KmacXOF256.init(&self, char[] key, String optional_customization = "") => self.k.init(key, optional_customization, is_xof_mode: true) @inline;

macro char[*] hash_128($outlen_bytes, char[] key, char[] data, String c = "") => xof(128, $outlen_bytes, key, data, c) @inline;
macro char[*] hash_256($outlen_bytes, char[] key, char[] data, String c = "") => xof(256, $outlen_bytes, key, data, c) @inline;

macro char[*] xof_128($outlen_bytes, char[] key, char[] data, String c = "") => xof(128, $outlen_bytes, key, data, c, $is_xof: true) @inline;
macro char[*] xof_256($outlen_bytes, char[] key, char[] data, String c = "") => xof(256, $outlen_bytes, key, data, c, $is_xof: true) @inline;
