// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
module sha3::parallel_hash_tests @test;

import sha3::tests_common;
import std::hash::sha3::parallel_hash;
import std::hash::sha3::parallel_hash_internal @public;
import std::hash::sha3::cshake;
import std::hash::sha3::nist @public;

import std::math;


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
    // /* tcId 53 */ test::eq(parallel_hash::xof_128(336 / 8, x"7908b829c19b5b22e2623d117450ca1a6e67", 16, c: "vsI&I{)#Z)JB$]s[-Wu`hCdE8U!%%={["), x"bb64392daed1f82bd2fe496da8e47cb25dae3a2fb08298287e9f7d4e0090ce3f88b722b4f285789a6466");
}

// This was the initial test I used to coerce ParallelHash into working (synchronously at first).
fn void the_desperation_pays_off()
{
    // see Sample #1 from https://csrc.nist.rip/groups/ST/toolkit/documents/Examples/ParallelHash_samples.pdf
    char[] x = x"000102030405060710111213141516172021222324252627";
    int b = 8;   // block size of 8
    int l = 256;   // want 32 bytes of hash (not XOF) output

    int n = (int)math::ceil(x.len / (float)b);
    test::@check(n == 3, "invalid block count `n`");

    // This doesn't directly test ParallelHash. Instead, it tests all of the underlying constructs,
    //   and outlines the (simplified) manner by which ParallelHash is able to achieve its goals.
    CShake128 cs;
    cs.init(PARALLEL_HASH, "");

    cs.update(nist::encode_length(LEFT, b, true));
    test::@check(x"0108" == nist::encode_length(LEFT, b, true), "Raw-byte `block_size` (b) should be `01 08`");

    // in the "real" PH, these are computed in parallel and converge in order at the end of all thread joins
    cs.update(cshake::xof_128(32, x[:8])[..]);   // block 0
    test::@check(cshake::xof_128(32, x[:8]) == x"2EA7A0601B9C5CB41E469F854077C1E33AAC94D39CE46163429ABCACFA992BBC", "Invalid first XOF output");

    cs.update(cshake::xof_128(32, x[8:8])[..]);   // block 1
    test::@check(cshake::xof_128(32, x[8:8]) == x"49867B4E0D7BA344078EEDE9BD7E8421679DED282A0E50CEE8F118361C087595", "Invalid second XOF output");

    cs.update(cshake::xof_128(32, x[16:8])[..]);   // block 2
    test::@check(cshake::xof_128(32, x[16:8]) == x"E68984758EE83E4B3F437C58625DA0CDE3EE6B06BF30F0F63DFF3915A5518FC8", "Invalid third XOF output");

    cs.update(nist::encode_length(RIGHT, n, true));
    test::@check(x"0301" == nist::encode_length(RIGHT, n, true), "Raw-byte encoded block count (n) should be `03 01`");

    cs.update(nist::encode_length(RIGHT, l / 8));
    test::@check(x"010002" == nist::encode_length(RIGHT, l / 8), "Raw-byte encoded output length (L) should be `01 00 02`");

    char[256 / 8] out; cs.final(out[..]);
    test::@check(x"ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5" == out, "Invalid final ParallelHash128 (non-XOF) value");
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
