// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
module std::hash::keccak::shake;

import std::hash::keccak::keccak;

macro typeid shake($security_level, $rounds = 24, $delimiter = 0x1F) @const
{
    return keccak::keccak($security_level, $rounds: $rounds, $delimiter: $delimiter);
}

macro char[*] xof($security_level, $outlen_bytes, char[] data, char delimiter_override = 0x1F)
{
    char[$outlen_bytes] into;

    $typefrom(shake($security_level)) s @noinit;
    defer s.wipe();
    s.init(delimiter_override);
    s.absorb(data);
    s.pad();
    s.squeeze(into[..]);

    return into;
}

alias Shake128 = $typefrom(shake(128));
alias Shake256 = $typefrom(shake(256));

macro char[*] hash_128($outlen_bytes, char[] data) => xof(128, $outlen_bytes, data) @inline;
macro char[*] hash_256($outlen_bytes, char[] data) => xof(256, $outlen_bytes, data) @inline;
