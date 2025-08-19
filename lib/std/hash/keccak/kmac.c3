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
}

fn void KmacContext.init(&self, char[] key, String optional_customization = "")
{
	self.c.init(KMAC, optional_customization);

	self.c.update(nist::@ct_encode_length(NistEncodingType.LEFT, RATE / 8));

	self.c.update(nist::encode_length(NistEncodingType.LEFT, key.len));
	self.c.update(key);

	self.c.fill_block();
}

fn void KmacContext.update(&self, char[] data) => self.c.update(data);

<*
 @require out.len > 0
*>
macro void KmacContext.final(&self, char[] out)
{
	self.c.update(nist::encode_length(NistEncodingType.RIGHT, out.len));
	self.c.pad();
	self.c.squeeze(out[..]);
}


// Names for the KMAC structures are a bit 
module std::hash::sha3::kmac;

import std::hash::sha3::kmac_internal @public;

macro typeid kmac($security_level) @const
{
	return (KmacContext { $security_level }).typeid;
}

macro char[*] xof($security_level, $outlen_bytes, char[] key, char[] data, String optional_customization = "")
{
	char [$outlen_bytes] result;

	$typefrom(kmac($security_level)) c;
	defer c.wipe();
	c.init(key, optional_customization);
	c.update(data);
	c.final(result[..]);

	return result;
}

alias Kmac128 = $typefrom(kmac(128));
alias Kmac256 = $typefrom(kmac(256));

macro char[*] hash_128($outlen_bytes, char[] key, char[] data, String c = "") => xof(128, $outlen_bytes, key, data, c) @inline;
macro char[*] hash_256($outlen_bytes, char[] key, char[] data, String c = "") => xof(256, $outlen_bytes, key, data, c) @inline;
