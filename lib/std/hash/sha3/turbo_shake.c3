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
module std::hash::turbo_shake;

import std::hash::shake_internal @public;

const ROUNDS = 12;

alias TurboShake128 = ShakeContext { 128, ROUNDS, 0x1F };
alias hash_128 = shake_internal::turbo_hash { 128, ROUNDS, 0x1F };
const RATE_128 = shake_internal::RATE { 128, ROUNDS, 0x1F };

alias TurboShake256 = ShakeContext { 256, ROUNDS, 0x1F };
alias hash_256 = shake_internal::turbo_hash { 256, ROUNDS, 0x1F };
const RATE_256 = shake_internal::RATE { 256, ROUNDS, 0x1F };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for TurboSHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] data, $delimiter = 0x1F)
{
    char[$outlen_bytes] result;

    shake_internal::turbo_hash{ $security_level, ROUNDS, 0x1F }(data, result[..], $delimiter);

    return result;
}
