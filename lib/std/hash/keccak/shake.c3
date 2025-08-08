// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
module std::hash::keccak::shake_internal { SECURITY_LEVEL, ROUNDS, DELIMITER } @private;

import std::hash::keccak::keccak_internal @public;

const char DEFAULT_DELIMITER = 0x1F;

const RATE = keccak_internal::RATE { 1600, SECURITY_LEVEL, ROUNDS, DELIMITER };

// NOTE: The Keccak module should take care of validating the module parameters.
alias ShakeContext = KeccakContext { 1600, SECURITY_LEVEL, ROUNDS, DELIMITER };

<*
 @require into.len > 0 : `Cannot use an empty SHAKE destination.`
*>
fn void hash_into(char[] data, char[] into, char delimiter_override = DELIMITER)
{
    ShakeContext s @noinit;
    defer s.wipe();

    s.init(delimiter_override);
    s.absorb(data);
    s.pad();
    s.squeeze(into);
}

// Quickly return an XOF output hash based on the SECURITY_LEVEL.
//   Note that, while this is doing essentially the same thing as `hash_into`, we absolutely
//   CANNOT allow `hash_into` to accept an optional delimiter value for SHAKE like TurboSHAKE.
//   This would create a more confusing API at the cost of trimming a few lines.
// fn void turbo_hash(char[] data, char[] into, char delimiter = 0x1F)
// {
//     ShakeContext s @noinit;
//     defer s.wipe();

//     s.init(delimiter);
//     s.absorb(data);
//     s.pad();
//     s.squeeze(into);
// }


module std::hash::keccak::shake;

import std::hash::keccak::shake_internal @public;

const ROUNDS = 24;

alias Shake128 = ShakeContext { 128, ROUNDS, 0x1F };
alias hash_128 = shake_internal::hash_into { 128, ROUNDS, 0x1F };
const RATE_128 = shake_internal::RATE { 128, ROUNDS, 0x1F };

alias Shake256 = ShakeContext { 256, ROUNDS, 0x1F };
alias hash_256 = shake_internal::hash_into { 256, ROUNDS, 0x1F };
const RATE_256 = shake_internal::RATE { 256, ROUNDS, 0x1F };

<*
@require $security_level == 128 ||| $security_level == 256 : `The security level for SHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] data)   // <-- this API intentionally does not expose DELIMITER
{
    char[$outlen_bytes] result;

    shake_internal::hash_into{ $security_level, ROUNDS, 0x1F }(data, result[..]);

    return result;
}
