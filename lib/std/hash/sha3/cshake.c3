// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// See: NIST SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//
module std::hash::cshake_common;

enum CShakeFunctionName : inline uint
{
    NONE,
    KMAC,
}

const String[] FUNCTION_NAMES = {
    "",
    "KMAC",
};


<*
 @require @typeis(FUNC_NAME, cshake_common::CShakeFunctionName) : "`FUNC_NAME` must be a NIST-approved constant string."
*>
module std::hash::cshake_internal { SECURITY_LEVEL, ROUNDS, DELIMITER, FUNC_NAME } @private;

import std::hash::shake;
import std::hash::shake_internal @public, std::hash::cshake_common;
import std::hash::nist @public;

const RATE = shake_internal::RATE { SECURITY_LEVEL, ROUNDS, DELIMITER };

alias UnderShake @local = ShakeContext{ SECURITY_LEVEL, ROUNDS, DELIMITER };

struct CShakeContext
{
    UnderShake under;
}

fn void hash_into(char[] data, char[] into, String optional_customization = "")
{
    if (optional_customization == "" && cshake_common::FUNCTION_NAMES[FUNC_NAME] == "")
    {
        return shake_internal::hash_into{ SECURITY_LEVEL, ROUNDS, 0x1F }(data, into);
    }

    CShakeContext c;
    defer c.wipe();

    c.init(optional_customization);
    c.update(data);
    c.pad();
    c.squeeze(into);
}

fn void CShakeContext.absorb(&self, char[] data) => self.under.absorb(data);
fn void CShakeContext.squeeze(&self, char[] into) => self.under.squeeze(into);
fn void CShakeContext.pad(&self) => self.under.pad();
fn void CShakeContext.wipe(&self) => self.under.wipe();
fn void CShakeContext.fill_block(&self) => self.under.fill_block();

fn void CShakeContext.init(&self, String optional_customization = "")
{
    String $function_name = cshake_common::FUNCTION_NAMES[FUNC_NAME];

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
 @require @typeis(FUNC_NAME, cshake_common::CShakeFunctionName) : "`FUNC_NAME` must be a NIST-approved constant string."
*>
module std::hash::cshake { FUNC_NAME };

import std::hash::cshake_internal @public, std::hash::cshake_common;

alias CShake128 = CShakeContext { 128, 24, 0x04, FUNC_NAME };
alias hash_128 = cshake_internal::hash_into { 128, 24, 0x04, FUNC_NAME };
const RATE_128 = cshake_internal::RATE { 128, 24, 0x04, FUNC_NAME };

alias CShake256 = CShakeContext { 256, 24, 0x04, FUNC_NAME };
alias hash_256 = cshake_internal::hash_into { 256, 24, 0x04, FUNC_NAME };
const RATE_256 = cshake_internal::RATE { 256, 24, 0x04, FUNC_NAME };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for SHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] data, String optional_customization = "")
{
    char[$outlen_bytes] result;

    cshake_internal::hash_into{ $security_level, 24, 0x04, FUNC_NAME }(data, result[..], optional_customization);

    return result;
}
