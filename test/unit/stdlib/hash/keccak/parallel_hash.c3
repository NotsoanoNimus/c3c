// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
module sha3::parallel_hash_tests @test;

import sha3::tests_common;
import std::hash::sha3::parallel_hash;
import std::hash::sha3::parallel_hash_internal @public;


// See: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ParallelHash-128-1.0
//   & https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ParallelHash-256-1.0
//
//  "internalProjection.json" files.
//
fn void parallel_hash_known_vectors() => @pool()
{
    // {
//           "tcId": 53,
//           "msg": "7908B829C19B5B22E2623D117450CA1A6E67",
//           "len": 144,
//           "blockSize": 16,
//           "customization": "vsI&I{)#Z)JB$]s[-Wu`hCdE8U!%%={[",
//           "md": "BB64392DAED1F82BD2FE496DA8E47CB25DAE3A2FB08298287E9F7D4E0090CE3F88B722B4F285789A6466",
//           "outLen": 336
//         },
    /* tgId  1 */
    /* tcId 53 */ test::eq(parallel_hash::xof_128(336 / 8, x"7908b829c19b5b22e2623d117450ca1a6e67", 16, c: "vsI&I{)#Z)JB$]s[-Wu`hCdE8U!%%={["), x"bb64392daed1f82bd2fe496da8e47cb25dae3a2fb08298287e9f7d4e0090ce3f88b722b4f285789a6466");
}

// fn void parallel_hash_empty()
// {
// }

// fn void parallel_hash_simple()
// {
// }

// fn void parallel_hash_interval()
// {
// }

// fn void parallel_hash_streamed()
// {
// }

// fn void parallel_hash_large() @if($feature(SLOW_TESTS)) => @pool()
// {
// }

// fn void parallel_hash_successive_xof_operations_128()
// {
// }

// fn void parallel_hash_successive_xof_operations_256()
// {
// }

// fn void parallel_hash_xof_vs_non_xof()
// {
// }
