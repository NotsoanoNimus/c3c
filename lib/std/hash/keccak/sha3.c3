// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
<*
@require values::@is_int(HASH_BITS) : `HASH_BITS must be an integer type.`
*>
module std::hash::keccak::sha3;

import std::hash::keccak::keccak;
import std::hash::keccak::keccak_internal @public;

macro typeid sha3($security_level) @local @const
{
    return (KeccakContext { 1600, $security_level, 24, 0x06 }).typeid;
}

macro char[*] hash($security_level, char[] data) @local
{
    return keccak::explicit_hash($security_level, 0x06, $security_level / 8, data);
}

alias Sha3_224 = $typefrom(sha3(224));
alias Sha3_256 = $typefrom(sha3(256));
alias Sha3_384 = $typefrom(sha3(384));
alias Sha3_512 = $typefrom(sha3(512));

fn char[224/8] hash_224(char[] data) => hash(224, data) @inline;
fn char[256/8] hash_256(char[] data) => hash(256, data) @inline;
fn char[384/8] hash_384(char[] data) => hash(384, data) @inline;
fn char[512/8] hash_512(char[] data) => hash(512, data) @inline;

