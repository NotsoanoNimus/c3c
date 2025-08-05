// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// See: NIST SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//
module std::hash::kmac;

import std::hash::cshake;
import std::hash::cshake_internal @public, std::hash::cshake_common;
import std::hash::nist @public;

alias Kmac128 = CShake128{ CShakeFunctionName.KMAC };
const RATE_128 = cshake::RATE_128 { CShakeFunctionName.KMAC };

alias Kmac256 = CShake256{ CShakeFunctionName.KMAC };
const RATE_256 = cshake::RATE_256 { CShakeFunctionName.KMAC };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for SHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] key, char[] data, String optional_customization = "")
{
    char[$outlen_bytes] result;

    $if $security_level == 128:
        CShake128 { CShakeFunctionName.KMAC } c;
    $else
        CShake256 { CShakeFunctionName.KMAC } c;
    $endif

    c.init(optional_customization);
    defer c.wipe();
    $if $security_level == 128:
        c.update(nist::@ct_encode_length(NistEncodingType.LEFT, RATE_128 / 8));
    $else
        c.update(nist::@ct_encode_length(NistEncodingType.LEFT, RATE_256 / 8));
    $endif
    c.update(nist::encode_length(NistEncodingType.LEFT, key.len));
    c.update(key);
    c.fill_block();

    c.update(data);
    c.update(nist::encode_length(NistEncodingType.RIGHT, $outlen_bytes));

    c.pad();
    c.squeeze(result[..]);

    return result;
}
