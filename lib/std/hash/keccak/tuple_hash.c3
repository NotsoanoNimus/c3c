// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// See: NIST SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//
<*
 @require types::is_int($typeof(SECURITY_LEVEL)) &&& SECURITY_LEVEL > 0 : "SECURITY_LEVEL must be a positive integer value greater than 0."
*>
module std::hash::sha3::tuple_hash_internal { SECURITY_LEVEL } @private;

import std::hash::sha3::keccak;
import std::hash::sha3::cshake;
import std::hash::sha3::nist @public;

const RATE = keccak::rate(SECURITY_LEVEL);

struct TupleHashContext
{
	inline $typefrom(cshake::cshake(SECURITY_LEVEL)) c;
	bool is_xof_mode;
}

fn void TupleHashContext.init(&self, String optional_customization = "", bool is_xof_mode = false)
{
	self.is_xof_mode = is_xof_mode;
	self.c.init(TUPLE_HASH, optional_customization);
}

// This is the more distinct feature of TupleHash: inputs are domain-separated.
//
// So, calling `th.update("abc")` then `th.update("def")` produces a ***DIFFERENT HASH***
//   than calling `th.update("ab")` then `th.update("cdef")`.
//
fn void TupleHashContext.update(&self, char[] data, char[]... extra)
{
    self.c.update(nist::encode_length(NistEncodingType.LEFT, data.len));
    self.c.update(data);

    foreach (v : extra)
    {
        self.c.update(nist::encode_length(NistEncodingType.LEFT, v.len));
        self.c.update(v);
    }
}

<*
 @require out.len > 0
*>
macro void TupleHashContext.final(&self, char[] out)
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


// Names for the KMAC structures are a bit 
module std::hash::sha3::tuple_hash;

import std::hash::sha3::tuple_hash_internal @public;

macro typeid tuple_hash($security_level) @local @const
{
	return (TupleHashContext { $security_level }).typeid;
}

// Set to local scope because only 128 and 256 should ever be exposed.
macro char[*] xof($security_level, $outlen_bytes, char[] data, char[]... extras, String optional_customization = "", bool $is_xof = false) @local
{
	char [$outlen_bytes] result;

	$typefrom(tuple_hash($security_level)) c;
	defer c.wipe();

	c.init(optional_customization, is_xof_mode: $is_xof);
	c.update(data, ...extras);
	c.final(result[..]);

	return result;
}

alias TupleHash128 = $typefrom(tuple_hash(128));
alias TupleHash256 = $typefrom(tuple_hash(256));

// The XOF variant of TupleHash uses a `right_encode(0)` at the end of the input stream.
//   This causes the output value to be completely different and not dependent on the length of the output buffer.
//   To better understand this, or to see the reference, search for NIST SP 800-185.
struct TupleHashXOF128
{
	inline $typefrom(tuple_hash(128)) th;
}
fn void TupleHashXOF128.init(&self, String optional_customization = "") => self.th.init(optional_customization, is_xof_mode: true) @inline;

struct TupleHashXOF256
{
	inline $typefrom(tuple_hash(256)) th;
}
fn void TupleHashXOF256.init(&self, String optional_customization = "") => self.th.init(optional_customization, is_xof_mode: true) @inline;

macro char[*] hash_128($outlen_bytes, char[] data, char[]... extras, String c = "") => xof(128, $outlen_bytes, data, ...extras, optional_customization: c) @inline;
macro char[*] hash_256($outlen_bytes, char[] data, char[]... extras, String c = "") => xof(256, $outlen_bytes, data, ...extras, optional_customization: c) @inline;

macro char[*] xof_128($outlen_bytes, char[] data, char[]... extras, String c = "") => xof(128, $outlen_bytes, data, ...extras, optional_customization: c, $is_xof: true) @inline;
macro char[*] xof_256($outlen_bytes, char[] data, char[]... extras, String c = "") => xof(256, $outlen_bytes, data, ...extras, optional_customization: c, $is_xof: true) @inline;
