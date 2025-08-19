// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// See: NIST SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//
<*
 @require types::is_int($typeof(SECURITY_LEVEL)) &&& SECURITY_LEVEL > 0 : "SECURITY_LEVEL must be a positive integer value greater than 0."
 @require types::is_int($typeof(ROUNDS)) &&& ROUNDS > 0 : "ROUNDS must be a positive integer value greater than 0."
 @require types::is_int($typeof(DELIMITER)) &&& DELIMITER >= 0 : "DELIMITER must be a positive integer value greater than or equal to 0."
*>
module std::hash::sha3::cshake_internal { SECURITY_LEVEL, ROUNDS, DELIMITER } @private;

import std::hash::sha3::shake;
import std::hash::sha3::keccak;
import std::hash::sha3::nist @public;

const RATE = keccak::rate(SECURITY_LEVEL);

struct CShakeContext
{
	inline $typefrom(shake::shake(SECURITY_LEVEL, ROUNDS, DELIMITER)) under;
}

macro void CShakeContext.init(&self, CShakeFunctionName $function = NONE, String optional_customization = "")
{
	String $function_name = $function.customizer;

	if (optional_customization == "" && $function_name == "")
	{
		return self.under.init(0x1F);   // override delimiter with default SHAKE delimiter (see NIST spec)
	}

	self.under.init();

	// Automatically encode and update the underlying SHAKE context with the rate length, N (func_name), and S (customization string) values.
	self.under.update(nist::@ct_encode_length(NistEncodingType.LEFT, RATE / 8));

	$if $function_name == "":
		self.under.update(nist::@ct_encode_length(NistEncodingType.LEFT, 0));   // encoded zero value (no/empty length)
	$else
		self.under.update(nist::@ct_encode_length(NistEncodingType.LEFT, $function_name.len));
		self.under.update($function_name[..]);
	$endif

	if (optional_customization == "")
	{
		self.under.update(nist::@ct_encode_length(NistEncodingType.LEFT, 0));   // encoded zero value (no/empty length)
	}
	else
	{
		self.under.update(nist::encode_length(NistEncodingType.LEFT, optional_customization.len));
		self.under.update(optional_customization);
	}

	// Fill block and be done.
	self.under.fill_block();
}



module std::hash::sha3::cshake;

import std::hash::sha3::cshake_internal @public;
import std::hash::sha3::nist @public;
import std::hash::sha3::shake;

macro typeid cshake($security_level, $rounds = 24, $delimiter = 0x04) @const
{
	return (CShakeContext { $security_level, $rounds, $delimiter }).typeid;
}

macro char[*] xof($security_level, $outlen_bytes, char[] data, String optional_customization = "", CShakeFunctionName $function = NONE, $rounds = 24, $delimiter = 0x04)
{
	if (optional_customization == "" && $function == NONE)
	{
		return shake::xof($security_level, $outlen_bytes, data);
	}

	char[$outlen_bytes] into;

	$typefrom(cshake($security_level, $rounds, $delimiter)) c;
	defer c.wipe();

	c.init($function, optional_customization);
	c.update(data);
	c.final(into[..]);

	return into;
}

alias CShake128 = $typefrom(cshake(128));
alias CShake256 = $typefrom(cshake(256));

macro char[*] hash_128($outlen_bytes, char[] data, String customizer = "", CShakeFunctionName $function = NONE, $rounds = 24, $delimiter = 0x04)
{
	return xof(128, $outlen_bytes, data, customizer, $function, $rounds, $delimiter) @inline;
}

macro char[*] hash_256($outlen_bytes, char[] data, String customizer = "", CShakeFunctionName $function = NONE, $rounds = 24, $delimiter = 0x04)
{
	return xof(256, $outlen_bytes, data, customizer, $function, $rounds, $delimiter) @inline;
}
