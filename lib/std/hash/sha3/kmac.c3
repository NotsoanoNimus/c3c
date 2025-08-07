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

import std::hash::sha3::cshake_p, std::hash::sha3::cshake_common;
import std::hash::sha3::nist @public;

struct KmacContext
{
    inline CShake { SECURITY_LEVEL } c;
}

fn void KmacContext.init(&self, char[] key, String optional_customization = "")
{
    self.c.init(KMAC, optional_customization);

    self.c.update(nist::@ct_encode_length(NistEncodingType.LEFT, cshake_p::RATE { SECURITY_LEVEL } / 8));

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

macro void hash_into(char[] key, char[] data, char[] into, String optional_customization = "")
{
    KmacContext c;
    defer c.wipe();
    c.init(key, optional_customization);
    c.update(data);
    c.final(into[..]);
}

macro char[*] @hash($outlen_bytes, char[] key, char[] data, String optional_customization = "")
{
    char[$outlen_bytes] result;

    hash_into(key, data, result[..], optional_customization);

    return result;
}


// Names for the KMAC structures are a bit 
module std::hash::sha3::kmac;

import std::hash::sha3::kmac_internal @public;

alias Kmac128 = KmacContext { 128 };
alias @hash_128 = kmac_internal::@hash { 128 };

alias Kmac256 = KmacContext { 256 };
alias @hash_256 = kmac_internal::@hash { 256 };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for SHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] key, char[] data, String optional_customization = "")
{
    return kmac_internal::@hash{ $security_level }($outlen_bytes, key, data, optional_customization);
}
