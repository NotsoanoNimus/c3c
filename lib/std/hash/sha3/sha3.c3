// Copyright (c) 2025-2026 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
module std::hash::sha3::sha3;

import std::hash::sha3::keccak;

const usz[] DIGEST_SIZES = { 224, 256, 384, 512 };

<*
@require @in(HASH_BITS, ...DIGEST_SIZES) : "You must use a valid SHA-3 digest size."
*>
fn char[HASH_BITS / 8] hash(char[] data) @generic(HASH_BITS)
{
	char[HASH_BITS / 8] result;
	Sha3{HASH_BITS} s @noinit;
	s.init();
	s.update(data);
	s.final(result[..]);
	return result;
}

<*
@require @in(HASH_BITS, ...DIGEST_SIZES) : "You must use a valid SHA-3 digest size."
*>
alias Sha3 @generic(HASH_BITS) = $typefrom(keccak::keccak(HASH_BITS, $delimiter: 0x06));
