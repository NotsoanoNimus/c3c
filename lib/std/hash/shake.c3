// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
module std::hash::shake_internal { SECURITY_LEVEL, ROUNDS } @private;

import std::hash::keccak_internal @public;

// NOTE: The Keccak module will take care of checking the module parameters for correctness here.
alias ShakeContext = KeccakContext { 1600, SECURITY_LEVEL, ROUNDS, 0x1F };

<*
 @require into.len > 0 : `Cannot use an empty SHAKE destination.`
*>
fn void hash_into(char[] data, char[] into)
{
    ShakeContext s @noinit;
    defer s.wipe();

    s.init();
    s.absorb(data);
    s.pad();
    s.squeeze(into);
}

// Quickly return an XOF output hash based on the SECURITY_LEVEL.
//   Note that, while this is doing essentially the same thing as `hash_into`, we absolutely
//   CANNOT allow `hash_into` to accept an optional delimiter value for SHAKE like TurboSHAKE.
//   This would create a more confusing API at the cost of trimming a few lines.
fn void turbo_hash(char[] data, char[] into, char delimiter = 0x1F)
{
    ShakeContext s @noinit;
    defer s.wipe();

    s.init(delimiter);
    s.absorb(data);
    s.pad();
    s.squeeze(into);
}


module std::hash::shake;

import std::hash::shake_internal @public;

const ROUNDS = 24;

alias Shake128 = ShakeContext { 128, ROUNDS };
alias hash_128 = shake_internal::hash_into { 128, ROUNDS };

alias Shake256 = ShakeContext { 256, ROUNDS };
alias hash_256 = shake_internal::hash_into { 256, ROUNDS };

<*
@require $security_level == 128 ||| $security_level == 256 : `The SECURITY_LEVEL for SHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] data)
{
    char[$outlen_bytes] result;

    shake_internal::hash_into{ $security_level, ROUNDS }(data, result[..]);

    return result;
}


// For KT and TurboSHAKE hashes, see: https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/
//   This should remain a separate module, even if it looks the same as the above, lest this become
//   confusing to maintainers. Again, it's not worth saving a few extra lines.
module std::hash::turbo_shake;

import std::hash::shake_internal @public;

const ROUNDS = 12;

alias TurboShake128 = ShakeContext { 128, ROUNDS };
alias hash_128 = shake_internal::turbo_hash { 128, ROUNDS };

alias TurboShake256 = ShakeContext { 256, ROUNDS };
alias hash_256 = shake_internal::turbo_hash { 256, ROUNDS };

<*
@require $security_level == 128 ||| $security_level == 256 : `The SECURITY_LEVEL for TurboSHAKE must be 128 or 256.`
@require $outlen_bytes > 0 : `Output length must be greater than zero.`
*>
macro char[*] @hash($security_level, $outlen_bytes, char[] data, $delimiter = 0x1F)
{
    char[$outlen_bytes] result;

    shake_internal::turbo_hash{ $security_level, ROUNDS }(data, result[..], $delimiter);

    return result;
}
