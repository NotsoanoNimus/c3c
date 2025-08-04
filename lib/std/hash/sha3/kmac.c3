// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// See: NIST SP 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//
module std::hash::kmac_internal @private;

import std::hash::cshake;
import std::hash::cshake_internal @public, std::hash::cshake_common;

// alias Kmac128 = CShake128{ CShakeFunctionName.KMAC };
// alias Kmac256 = CShake256{ CShakeFunctionName.KMAC };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for SHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] key, char[] data, String optional_customization = "")
{
    // TODO: Prepend hash/rate and key and such
    return cshake::@hash{ CShakeFunctionName.KMAC }($security_level, $outlen_bytes, data, optional_customization);
}
