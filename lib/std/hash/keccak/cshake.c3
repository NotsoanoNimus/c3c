// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// See: NIST SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//
module std::hash::keccak::cshake_common;

enum CShakeFunctionName : int (String customizer)
{
    NONE = "",
    KMAC = "KMAC",
}


<*
 @require types::is_int($typeof(SECURITY_LEVEL)) &&& SECURITY_LEVEL > 0 : "SECURITY_LEVEL must be a positive integer value greater than 0."
 @require types::is_int($typeof(ROUNDS)) &&& ROUNDS > 0 : "ROUNDS must be a positive integer value greater than 0."
 @require types::is_int($typeof(DELIMITER)) &&& DELIMITER >= 0 : "DELIMITER must be a positive integer value greater than or equal to 0."
*>
module std::hash::keccak::cshake_internal { SECURITY_LEVEL, ROUNDS, DELIMITER } @private;

import std::hash::keccak::shake;
import std::hash::keccak::shake_internal @public, std::hash::keccak::cshake_common;
import std::hash::keccak::nist @public;

const RATE = shake_internal::RATE { SECURITY_LEVEL, ROUNDS, DELIMITER };

struct CShakeContext
{
    inline ShakeContext{ SECURITY_LEVEL, ROUNDS, DELIMITER } under;
}

macro void hash_into(char[] data, char[] into, CShakeFunctionName $function = NONE, String optional_customization = "")
{
    if (optional_customization == "" && $function.customizer == "")
    {
        return shake_internal::hash_into{ SECURITY_LEVEL, ROUNDS, 0x1F }(data, into);
    }

    CShakeContext c;
    defer c.wipe();

    c.init($function, optional_customization);
    c.update(data);
    c.pad();
    c.squeeze(into);
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

fn void CShakeContext.update(&self, char[] data) => self.under.update(data);

macro char[*] CShakeContext.final(&self) => self.under.final();


<*
 Parameterized CShake module with a custom security level. Implementations should prefer
 to use common or well-known CShake variants in the 'cshake' module.

 @require types::is_int($typeof(SECURITY_LEVEL)) &&& SECURITY_LEVEL > 0 : "SECURITY_LEVEL must be a positive integer value greater than 0."
*>
module std::hash::keccak::cshake_p { SECURITY_LEVEL };

import std::hash::keccak::cshake_internal @public, std::hash::keccak::cshake_common;

const RATE = cshake_internal::RATE { SECURITY_LEVEL, 24, 0x04 };

alias CShake = CShakeContext { SECURITY_LEVEL, 24, 0x04 };
alias hash = cshake_internal::hash_into { SECURITY_LEVEL, 24, 0x04 };


module std::hash::keccak::cshake;

import std::hash::keccak::cshake_p;

alias CShake128 = CShake { 128 };
alias hash_128 = cshake_p::hash { 128 };

alias CShake256 = CShake { 256 };
alias hash_256 = cshake_p::hash { 256 };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for SHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] data, String optional_customization = "")
{
    char[$outlen_bytes] result;

    cshake_p::hash{ $security_level }(data, result[..], NONE, optional_customization);

    return result;
}
