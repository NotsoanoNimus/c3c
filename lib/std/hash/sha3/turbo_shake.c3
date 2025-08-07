// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// For KT and TurboSHAKE hashes, see: https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/
//
//   TurboSHAKE allows the user to specify their own DELIMITER value at runtime.
//
//   This should remain a separate module, even thoguh it's almost the same as SHAKE, lest this
//   become very confusing to maintainers. It's not worth folding this into SHAKE to save a few
//   extra lines.
//
module std::hash::sha3::turbo_shake_p { SECURITY_LEVEL };

import std::hash::sha3::shake_internal @public;

alias TurboShakeContext = ShakeContext { SECURITY_LEVEL, 12, 0x1F };
alias hash_into = shake_internal::hash_into { SECURITY_LEVEL, 12, 0x1F };


module std::hash::sha3::turbo_shake;

import std::hash::sha3::turbo_shake_p;

alias TurboShake128 = TurboShakeContext { 128 };
alias hash_128 = turbo_shake_p::hash_into { 128 };

alias TurboShake256 = TurboShakeContext { 256 };
alias hash_256 = turbo_shake_p::hash_into { 256 };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for TurboSHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] data, char $delimiter = 0x1F)
{
    char[$outlen_bytes] result;

    turbo_shake_p::hash_into{ $security_level }(data, result[..], $delimiter);

    return result;
}
