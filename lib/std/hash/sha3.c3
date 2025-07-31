// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
<*
@require values::@is_int(HASH_BITS) : `HASH_BITS must be an integer type.`
*>
module std::hash::sha3_internal { HASH_BITS } @private;

import std::hash::keccak @public;


const HASH_BYTES = HASH_BITS / 8;

alias Sha3Context = KeccakContext { 1600, HASH_BITS, 24, 0x06 };   // FIPS-202 defines these constants for SHA-3


fn char[HASH_BYTES] hash(char[] data)
{
    Sha3Context s @noinit;
    s.init();
    s.update(data);
    return s.final();
}


module std::hash::sha3;

import std::hash::sha3_internal @public;


alias Sha3Context_224 = Sha3Context { 224 };
alias hash_224 = sha3_internal::hash { 224 };

alias Sha3Context_256 = Sha3Context { 256 };
alias hash_256 = sha3_internal::hash { 256 };

alias Sha3Context_384 = Sha3Context { 384 };
alias hash_384 = sha3_internal::hash { 384 };

alias Sha3Context_512 = Sha3Context { 512 };
alias hash_512 = sha3_internal::hash { 512 };

