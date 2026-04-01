// Copyright (c) 2026 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// This implementation is based on FIPS-205 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
//
module std::crypto::slh_dsa @private;

// TODO: Section 3.1, security requirement for destruction: pointers should be used to pass sensitive data as much as possible
//       This is to limit how often stack memory would otherwise need to be explicitly zeroized in order to protect keys/data.

import std::math;

<*
 Compile-time 'ceil' implementation.

 @require $val < uint.max
*>
macro @ct_ceil($val) @const => (uint)$val + ((double)(uint)$val < $val ? 1 : 0);

<*
 Algorithm 2.

 @require x.len == $n : "The input byte-string `x` is not a suficient length."
*>
macro to_int(x, $n)
{
	uint128 total;
	for (uint i = 0; i < $n; i++) total = (total * 256) + x[i];
	$switch:
		$case $n == 1: return (char)total;
		$case $n == 2: return (ushort)total;
		$case $n <= 4: return (uint)total;
		$case $n <= 8: return (ulong)total;
		$case $n <= 16: return total;
		$default: $error "Invalid 'n' constraint on Algorithm 2 (`to_int`).";
	$endswitch
}

<*
 Algorithm 3.
*>
macro char[*] to_byte(x, $n)
{
	char[$n] res;
	var total = x;
	for (uint i = 0; i < $n; i++)
	{
		res[$n - 1 - i] = (char)total;
		total >>= 8;
	}
	return res;
}

<*
 Algorithm 4.

 @require byte_string.len >= math::ceil(($out_len * $b) / 8.0) : "Input byte string length is insufficient."
*>
macro uint128[*] base_2b(char[] byte_string, uint $b, uint $out_len)
{
	uint128[$out_len] res;
	uint128 total;
	uint in, bits;
	for (usz out = 0; out < $out_len; out++)
	{
		while (bits < $b)
		{
			total = (total << 8) + byte_string[in];
			in++;   // TODO: move this into the previous statement
			bits += 8;
		}
		bits -= $b;
		res[out] = (total >> bits) % (uint128)math::pow(2, $b);
	}
	return res;
}

<*
 See Table 2 of FIPS-205. Rather than drafting countless if-else compile-time statements to satisfy
 the varying permutations set forth in the standard, we instead just bundle the parameters together
 and select it a single time (also at compile-time).
*>
struct SlhDsaParameters
{
	uint n;
	uint h;   // the total height of the hypertree (d * hp)
	uint d;   // depth of XMSS trees within the SLH-DSA hypertree
	uint hp;   // height of each Merkle Tree comprising a single XMSS signature
	uint a;
	uint k;
	uint lg_w;
	uint m;
	uint category;
	uint pubkey_len;
	uint signature_len;
}
const SlhDsaParameters[] PARAMS_SET = {
	{ 16, 63,  7, 9, 12, 14, 4, 30, 1, 32,  7_856 },   // 128s
	{ 16, 66, 22, 3,  6, 33, 4, 34, 1, 32, 17_088 },   // 128f
	{ 24, 63,  7, 9, 14, 17, 4, 39, 3, 48, 16_224 },   // 192s
	{ 24, 66, 22, 3,  8, 33, 4, 42, 3, 48, 35_664 },   // 192f
	{ 32, 64,  8, 8, 14, 22, 4, 47, 5, 64, 29_792 },   // 256s
	{ 32, 68, 17, 4,  9, 35, 4, 49, 5, 64, 49_856 },   // 256f
};

macro SlhDsaParameters select_params($strength, SlhDsaMode $mode) @const
{
	return PARAMS_SET[($strength / 8 - 2) * 2 + $mode.ordinal];
}

constdef SlhDsaAddressType : inline uint
{
	WOTS_HASH = 0,
	WOTS_PK = 1,
	TREE = 2,
	FORS_TREE = 3,
	FORS_ROOTS = 4,
	WOTS_PRF = 5,
	FORS_PRF = 6,
}

struct WotsPlusHashAddress @packed   // type = WOTS_HASH
{
	uint key_pair;
	uint chain;
	uint hash;
}

struct WotsPlusPkAddress @packed   // type = WOTS_PK
{
	uint key_pair;
	char[8] _pad;
}

struct HashTreeAddress @packed   // type = TREE
{
	char[4] _pad;
	uint height;
	uint index;
}

struct ForsTreeAddress @packed   // type = FORS_TREE
{
	uint key_pair;
	uint height;
	uint index;
}

struct ForsRootsCompressionAddress @packed   // type = FORS_ROOTS
{
	uint key_pair;
	char[8] _pad;
}

struct WotsKeygenAddress @packed   // type = WOTS_PRF
{
	uint key_pair;
	uint chain;
	uint hash;   // should always be zero
}

struct ForsKeygenAddress @packed   // type = FORS_PRF
{
	uint key_pair;
	uint height;   // should always be zero
	uint index;
}

struct SlhDsaAddress @align(usz.sizeof) @packed
{
	uint layer;   // height of an XMSS tree within the hypertree
	uint[3] tree;   // position of an XMSS tree within a layer of the hypertree
	SlhDsaAddressType type;   // use-case-dependent type of address
	union   // offset: 20
	{
		char[12] raw;
		WotsPlusHashAddress wots_hash;
		WotsPlusPkAddress wots_pk;
		HashTreeAddress hash_tree;
		ForsTreeAddress fors_tree;
		ForsRootsCompressionAddress fors_roots;
		WotsKeygenAddress wots_prf;
		ForsKeygenAddress fors_prf;
	}
}
fn bool SlhDsaAddress.eq(&self, SlhDsaAddress other) @operator(==) => @as_char_view(*self) == @as_char_view(other);

fn void SlhDsaAddress.set_layer_address(&self, uint l) => @as_char_view(self.layer)[..] = to_byte(l, 4)[..];
fn void SlhDsaAddress.set_tree_address(&self, uint128 t) => @as_char_view(self.tree)[..] = to_byte(t, 12)[..];
fn void SlhDsaAddress.set_type_and_clear(&self, SlhDsaAddressType y)
{
	mem::zero_volatile(@as_char_view(*self)[16..]);
	@as_char_view(self.type)[..] = to_byte(y, uint.sizeof)[..];
}
fn void SlhDsaAddress.set_key_pair_address(&self, uint128 i) => @as_char_view(self.wots_hash.key_pair)[..] = to_byte(i, uint.sizeof)[..];
fn void SlhDsaAddress.set_chain_address(&self, uint128 i) => @as_char_view(self.wots_hash.chain)[..] = to_byte(i, uint.sizeof)[..];
macro SlhDsaAddress.set_tree_height(&self, uint128 i) => self.set_chain_address(i);
fn void SlhDsaAddress.set_hash_address(&self, uint128 i) => @as_char_view(self.wots_hash.hash)[..] = to_byte(i, uint.sizeof)[..];
macro SlhDsaAddress.set_tree_index(&self, uint128 i) => self.set_hash_address(i);
fn uint128 SlhDsaAddress.get_key_pair_address(&self) => (uint128)to_int(@as_char_view(self.wots_hash.key_pair), uint.sizeof);
fn uint128 SlhDsaAddress.get_tree_index(&self) => (uint128)to_int(@as_char_view(self.wots_hash.hash), uint.sizeof);


module std::crypto::slh_dsa;

import std::crypto::entropy, std::collections::pair;
import std::hash::sha256, std::hash::sha512, std::crypto::shake;

// TODO: Consider moving these types of aliases up into Keccak stuff.
alias Shake128 = Shake{128};
alias Shake256 = Shake{256};

enum SlhDsaHashType
{
	SHA2,
	SHAKE,
}

enum SlhDsaMode
{
	SMALL,
	FAST,
}

<*
 Each node is an SLH-DSA "unit" that ends up being `N` bytes wide.

 @require @in(Z, 16, 24, 32) : "The `N` size must be set to the appropriate supported key size: 16, 24, or 32."
*>
alias SlhDsaNode <Z> = char[Z];

<*
 See Section 9.1 of FIPS-205.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
*>
struct SlhDsaPublicKey <N>
{
	SlhDsaNode{N >> 3} root;
	SlhDsaNode{N >> 3} seed;
}
fn bool SlhDsaPublicKey.eq(&self, SlhDsaPublicKey{N} other) @operator(==) => member_eq(*self, other);

<*
 See Section 9.1 of FIPS-205.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
*>
struct SlhDsaPrivateKey <N>
{
	SlhDsaNode{N >> 3} seed;   // used to generate all WOTS+ and FORS pk elements
	SlhDsaNode{N >> 3} prf;   // used to generate a randomization value for randomized message hashing
	SlhDsaPublicKey{N} pub;
}
fn bool SlhDsaPrivateKey.eq(&self, SlhDsaPrivateKey{N} other) @operator(==) => member_eq(*self, other);

<* A single object that contains both the public and private keys. *>
struct SlhDsaKeyPair <N>
{
	SlhDsaPublicKey{N} pubkey;
	SlhDsaPrivateKey{N} privkey;
}
fn bool SlhDsaKeyPair.eq(&self, SlhDsaKeyPair{N} other) @operator(==) => member_eq(*self, other);

// TODO: Refactor and remove macros here
// TODO: Allow PRNG hook to be applied here
<*
 Algorithm 21.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
*>
macro SlhDsaKeyPair{N}? keygen(SlhDsaHashType $type = SHAKE, SlhDsaMode $mode = FAST) <N>
{
	SlhDsaPrivateKey{N} privkey;
	SlhDsaPublicKey{N} pubkey;
	entropy::fill(privkey.seed[..])!;
	entropy::fill(privkey.prf[..])!;
	entropy::fill(pubkey.seed[..])!;
	return keygen_internal{N >> 3, $type, $mode}(privkey.seed, privkey.prf, pubkey.seed);
}

<*
 Algorithm 22.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
 @require context.len <= 255 : "The `context` byte-string has a maximum length of 255 bytes."

 @return? entropy::SECURE_RANDOM_UNAVAILABLE : "The cryptographically-secure PRNG is not available. You may need to set `hedged` to `false` to continue."
*>
macro char[]? sign(Allocator allocator, SlhDsaPrivateKey{N} privkey, char[] message, char[] context = {},
	bool hedged = true, SlhDsaNode{N >> 3} additional_randomness = {}, SlhDsaHashType $type = SHAKE, SlhDsaMode $mode = FAST) <N> => @pool()
{
	var $SigType = SlhDsaSignature{N >> 3, $type, $mode};
	char[] res = alloc::new_array(allocator, char, $SigType.sizeof);
	if (hedged && additional_randomness == (SlhDsaNode{N >> 3}){}) entropy::fill(additional_randomness[..])!;
	char[] message_p = alloc::alloc_array(tmem, char, 1 + 1 + context.len + message.len);
	message_p[0] = 0;
	message_p[1] = (char)context.len;
	message_p[2 : context.len] = context[..];
	message_p[2 + context.len ..] = message[..];
	$SigType signature = sign_internal{N >> 3, $type, $mode}(message_p, privkey, addrnd: additional_randomness, hedged: hedged);
	res[..] = @as_char_view(signature)[..];
	return res;
}

enum SlhDsaPreHashType : (UInt128BE oid)
{
	SHA256    { { 0x0609608648016503040201ull } },
	SHA512    { { 0x0609608648016503040203ull } },
	SHAKE128  { { 0x060960864801650304020Bull } },
	SHAKE256  { { 0x060960864801650304020Cull } },
}

// TODO TODO TODO: Again, way too long to be a macro - figure this out
<*
 Algorithm 23.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
 @require context.len <= 255 : "The `context` byte-string has a maximum length of 255 bytes."

 @return? entropy::SECURE_RANDOM_UNAVAILABLE : "The cryptographically-secure PRNG is not available. You may need to set `hedged` to `false` to continue."
 @return? NOT_FOUND : "The pre-hash type is not valid."
*>
macro char[]? hash_sign(Allocator allocator, SlhDsaPrivateKey{N} privkey, char[] message, SlhDsaPreHashType pre_hash,
	char[] context = {}, bool hedged = true, SlhDsaNode{N >> 3} additional_randomness = {}, SlhDsaHashType $type = SHAKE, SlhDsaMode $mode = FAST) <N> => @pool()
{
	var $SigType = $typeof(SlhDsaSignature{N >> 3, $type, $mode});
	char[64] tmp_hash;
	char[] hash;
	if (hedged && additional_randomness == (SlhDsaNode{N >> 3}){}) entropy::fill(additional_randomness[..])!;
	switch (pre_hash)
	{
		case SHA256:
			tmp_hash[:32] = sha256::hash(message)[..];
			hash = tmp_hash[:32];
		case SHA512:
			tmp_hash[:32] = sha512::hash(message)[..];
			hash = tmp_hash[:64];
		case SHAKE128:
			shake::xof_into(128, tmp_hash[:32], message);
			hash = tmp_hash[:32];
		case SHAKE256:
			shake::xof_into(256, tmp_hash[:64], message);
			hash = tmp_hash[:64];
		default: return NOT_FOUND~;
	}
	char[] message_p = alloc::alloc_array(tmem, char, 1 + 1 + context.len + 11 + hash.len);
	message_p[0] = 1;
	message_p[1] = context.len;
	message_p[2 : context.len] = context[..];
	message_p[2 + context.len : 11] = @as_char_view(pre_hash.oid)[^11..];
	message_p[2 + context.len + 11 ..] = hash[..];
	$SigType signature = sign_internal{N >> 3, $type, $mode}(message_p, privkey, addrnd: additional_randomness, hedged: hedged);
	res[..] = @as_char_view(signature)[..];
	return res;
}

<*
 NOTE: Per specification requirements, a random number generator with a strength of _at least_ `8N` bits _must_ be used.

 @require @in(N, 16, 24, 32) : "The SLH-DSA 'n' value must be a supported integer length (16, 24, or 32 bytes)."
 @require $typeof(HASH_TYPE) == SlhDsaHashType : "`HASH_TYPE` must be a valid value from the `SlhDsaHashType` enum."
 @require $typeof(MODE) == SlhDsaMode : "`MODE` must be a valid value from the `SlhDsaMode` enum."
*>
module std::crypto::slh_dsa <N, HASH_TYPE, MODE>;

<*
 Algorithm 24.
*>
macro bool verify(char[] message, SlhDsaSignature sig, SlhDsaPublicKey{N << 3} pubkey, char[] context = {}) => @pool()
{
	if (context.len > 255) return false;   // any `context` string over 255 bytes is automatically invalid
	char[] message_p = alloc::alloc_array(tmem, char, 1 + 1 + context.len + message.len);
	message_p[0] = 0;
	message_p[1] = context.len;
	message_p[2 : context.len] = context[..];
	message_p[2 + context.len ..] = message[..];
	return verify_internal(message_p, sig, pubkey);
}

<*
 Algorithm 25.

 @return? NOT_FOUND : "The pre-hash type is not valid."
*>
macro bool hash_verify(char[] message, SlhDsaPreHashType pre_hash, SlhDsaSignature sig, SlhDsaPublicKey{N << 3} pubkey, char[] context = {}) => @pool()
{
	if (context.len > 255) return false;   // any `context` string over 255 bytes is automatically invalid
	char[64] tmp_hash;
	char[] hash;
	switch (pre_hash)
	{
		case SHA256:
			tmp_hash[:32] = sha256::hash(message)[..];
			hash = tmp_hash[:32];
		case SHA512:
			tmp_hash[:32] = sha512::hash(message)[..];
			hash = tmp_hash[:64];
		case SHAKE128:
			shake::xof_into(128, tmp_hash[:32], message);
			hash = tmp_hash[:32];
		case SHAKE256:
			shake::xof_into(256, tmp_hash[:64], message);
			hash = tmp_hash[:64];
		default: return NOT_FOUND~;
	}
	char[] message_p = alloc::alloc_array(tmem, char, 1 + 1 + context.len + 11 + hash.len);
	message_p[0] = 1;
	message_p[1] = context.len;
	message_p[2 : context.len] = context[..];
	message_p[2 + context.len : 11] = @as_char_view(pre_hash.oid)[^11..];
	message_p[2 + context.len + 11 ..] = hash[..];
	return verify_internal(message_p, sig, pubkey);
}


<*
 NOTE: Per specification requirements, a random number generator with a strength of _at least_ `8N` bits _must_ be used.

 @require @in(N, 16, 24, 32) : "The SLH-DSA 'n' value must be a supported integer length (16, 24, or 32 bytes)."
 @require $typeof(HASH_TYPE) == SlhDsaHashType : "`HASH_TYPE` must be a valid value from the `SlhDsaHashType` enum."
 @require $typeof(MODE) == SlhDsaMode : "`MODE` must be a valid value from the `SlhDsaMode` enum."
*>
module std::crypto::slh_dsa <N, HASH_TYPE, MODE> @private;

import std::math, std::crypto::shake;

<* The compile-time parameter set selected based on the generic module parameters. *>
const PARAMS = select_params(N, MODE);

<*
 Used to generate the secret values for WOTS+ and FORS private keys.
*>
fn SlhDsaNode{N} prf(SlhDsaNode{N} pubkey_seed, SlhDsaNode{N} privkey_seed, SlhDsaAddress* adrs)
{
	SlhDsaNode{N} result;
	$if HASH_TYPE == SHAKE:
		Shake256 s;
		s.init();
		s.update(@as_char_view(pubkey_seed));
		s.update(@as_char_view(*adrs));
		s.update(@as_char_view(privkey_seed));
		s.final(result[..]);
	$else
		return NOT_IMPLEMENTED~!!;
	$endif
	return result;
}

<*
 Pseudorandom function which generates the randomizer (`R`) for the randomized hashing
 of the signed message.
*>
fn SlhDsaNode{N} prf_msg(SlhDsaNode{N} privkey_prf, SlhDsaNode{N} opt_rand, char[] message)
{
	SlhDsaNode{N} result;
	$if HASH_TYPE == SHAKE:
		Shake256 s;
		s.init();
		s.update(@as_char_view(privkey_prf));
		s.update(@as_char_view(opt_rand));
		s.update(message);
		s.final(result[..]);
	$else
		return NOT_IMPLEMENTED~!!;
	$endif
	return result;
}

<*
 Used to generate the digest of the message to be signed.
*>
fn char[PARAMS.m] hash_msg(SlhDsaNode{N} randomizer, SlhDsaPublicKey{N << 3} pubkey, char[] message)
{
	char[PARAMS.m] result;
	$if HASH_TYPE == SHAKE:
		Shake256 s;
		s.init();
		s.update(@as_char_view(randomizer));
		s.update(@as_char_view(pubkey.seed));
		s.update(@as_char_view(pubkey.root));
		s.update(message);
		s.final(result[..]);
	$else
		return NOT_IMPLEMENTED~!!;
	$endif
	return result;
}

<*
 Common helper function for similar SHAKE operations with Tl, F, and H constructions.
*>
fn SlhDsaNode{N} _simple_shake(SlhDsaNode{N} pubkey_seed, SlhDsaAddress* adrs, char[] message)
{
	SlhDsaNode{N} res;
	Shake256 s;
	s.init();
	s.update(@as_char_view(pubkey_seed));
	s.update(@as_char_view(*adrs));
	s.update(message);
	s.final(res[..]);
	return res;
}

<*
 Hash function that maps an L-byte message to an N-byte message.

 @require message.len % N == 0 : "The `T` function requires the `message` length to be a multiple of `N`."
*>
fn SlhDsaNode{N} t(SlhDsaNode{N} pubkey_seed, SlhDsaAddress* adrs, char[] message)
{
	$if HASH_TYPE == SHAKE:
		return _simple_shake(pubkey_seed, adrs, message);
	$else
		return NOT_IMPLEMENTED~!!;
	$endif
}

<*
 Special case of Tl which takes an input byte string of exactly `2 * N` bytes in length.
*>
fn SlhDsaNode{N} h(SlhDsaNode{N} pubkey_seed, SlhDsaAddress* adrs, SlhDsaNode{N}[2] message)
{
	$if HASH_TYPE == SHAKE:
		return _simple_shake(pubkey_seed, adrs, @as_char_view(message));
	$else
		return NOT_IMPLEMENTED~!!;
	$endif
}

<*
 Hash function that maps an N-byte input to a different N-byte output.
*>
fn SlhDsaNode{N} f(SlhDsaNode{N} pubkey_seed, SlhDsaAddress* adrs, SlhDsaNode{N} message)
{
	$if HASH_TYPE == SHAKE:
		return _simple_shake(pubkey_seed, adrs, @as_char_view(message));
	$else
		return NOT_IMPLEMENTED~!!;
	$endif
}


// ============================================================================
// ============================================================================
// ============================================================================
// WOTS+ (Section 5) - related algorithms, constants, helpers, et al.
//

// In all approved parameter sets for SLH-DSA, lg_w is always set to 4. This allows us to make precalculations.
const uint WOTS_W = 16;
const uint WOTS_LG_W = 4;
const uint WOTS_LEN1 = 2 * N;
const uint WOTS_LEN2 = 3;
const uint WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

<*
 Algorithm 5.
*>
fn SlhDsaNode{N} chain(SlhDsaNode{N} x, uint128 i, uint128 s, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress* adrs) => @pool()
{
	SlhDsaNode{N} tmp = x;
	for (uint128 j = i; j < i + s; j++)
	{
		adrs.set_hash_address(j);
		tmp = f(pubkey.seed, adrs, tmp);
	}
	return tmp;
}

<*
 Algorithm 6.
*>
fn SlhDsaNode{N} wots_pk_gen(SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress* adrs)
{
	SlhDsaAddress sk_adrs = *adrs;
	sk_adrs.set_type_and_clear(WOTS_PRF);
	sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	SlhDsaNode{N}[WOTS_LEN] chains;
	for (usz i = 0; i < WOTS_LEN; i++)
	{
		sk_adrs.set_chain_address(i);
		SlhDsaNode{N} sk = prf(privkey.pub.seed, privkey.seed, &sk_adrs);
		adrs.set_chain_address(i);
		chains[i] = chain(sk, 0, WOTS_W - 1, privkey.pub, adrs);
	}
	SlhDsaAddress wots_pk_adrs = *adrs;
	wots_pk_adrs.set_type_and_clear(WOTS_PK);
	wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	return t(privkey.pub.seed, &wots_pk_adrs, @as_char_view(chains));
}

<*
 Algorithm 7.
*>
fn SlhDsaNode{N}[WOTS_LEN] wots_sign(SlhDsaNode{N} m, SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress* adrs)
{
	SlhDsaNode{N}[WOTS_LEN] sig;
	uint128 csum;
	uint128[WOTS_LEN] msg;
	msg[:WOTS_LEN1] = base_2b(m[..], WOTS_LG_W, WOTS_LEN1)[..];
	for (uint i = 0; i < WOTS_LEN1; i++) csum += WOTS_W - 1 - msg[i];
	csum <<= 4; // this comes from the following formula: (8 - ((WOTS_LEN2 * WOTS_LG_W) % 8)) % 8
	msg[WOTS_LEN1:WOTS_LEN2] = base_2b(to_byte(csum, 2)[..], WOTS_LG_W, WOTS_LEN2)[..];   // again, simplified
	SlhDsaAddress sk_adrs = *adrs;
	sk_adrs.set_type_and_clear(WOTS_PRF);
	sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	for (uint i = 0; i < WOTS_LEN; i++)
	{
		sk_adrs.set_chain_address(i);
		SlhDsaNode{N} sk = prf(privkey.pub.seed, privkey.seed, &sk_adrs);
		adrs.set_chain_address(i);
		sig[i] = chain(sk, 0, msg[i], privkey.pub, adrs);
	}
	return sig;
}

<*
 Algorithm 8.
*>
fn SlhDsaNode{N} wots_pk_from_sig(SlhDsaNode{N}[WOTS_LEN] sig, SlhDsaNode{N} m, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress* adrs)
{
	SlhDsaNode{N}[WOTS_LEN] tmp;
	uint128 csum;
	uint128[WOTS_LEN] msg;
	msg[:WOTS_LEN1] = base_2b(m[..], WOTS_LG_W, WOTS_LEN1)[..];
	for (uint i = 0; i < WOTS_LEN1; i++) csum += WOTS_W - 1 - msg[i];
	csum <<= 4;
	msg[WOTS_LEN1:WOTS_LEN2] = base_2b(to_byte(csum, 2)[..], WOTS_LG_W, WOTS_LEN2)[..];
	for (uint i = 0; i < WOTS_LEN; i++)
	{
		adrs.set_chain_address(i);
		tmp[i] = chain(sig[i], msg[i], WOTS_W - 1 - msg[i], pubkey, adrs);
	}
	SlhDsaAddress wots_pk_adrs = *adrs;
	wots_pk_adrs.set_type_and_clear(WOTS_PK);
	wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	return t(pubkey.seed, &wots_pk_adrs, @as_char_view(tmp));
}


// ============================================================================
// ============================================================================
// ============================================================================
// XMSS (Section 6) - related algorithms, constants, helpers, et al.
//

<*
 An XMSS signature consists of a WOTS+ signature and an authentication path through a
 Merkle Tree, which always provides a path to the root node (the XMSS signature).
*>
const uint XMSS_SIGNATURE_LEN = (WOTS_LEN + XMSS_HEIGHT) * N;

<* The height of a single XMSS Merkle Tree. *>
const uint XMSS_HEIGHT = PARAMS.hp;

struct XmssSignature @packed
{
	SlhDsaNode{N}[WOTS_LEN] wots;
	SlhDsaNode{N}[XMSS_HEIGHT] auth_path;
}
fn bool XmssSignature.eq(&self, XmssSignature other) @operator(==) => member_eq(*self, other);

<*
 Algorithm 9.
*>
fn SlhDsaNode{N} xmss_node(SlhDsaPrivateKey{N << 3} privkey, uint128 node_index, uint128 node_height, SlhDsaAddress* adrs)
{
	if (node_height == 0)
	{
		adrs.set_type_and_clear(WOTS_HASH);
		adrs.set_key_pair_address(node_index);
		return wots_pk_gen(privkey, adrs);
	}
	SlhDsaNode{N} left  = xmss_node(privkey, 2 * node_index, node_height - 1, adrs);
	SlhDsaNode{N} right = xmss_node(privkey, 2 * node_index + 1, node_height - 1, adrs);
	adrs.set_type_and_clear(TREE);
	adrs.set_tree_height(node_height);
	adrs.set_tree_index(node_index);
	return h(privkey.pub.seed, adrs, (SlhDsaNode{N}[2]){ left, right });
}

<*
 Algorithm 10.
*>
fn XmssSignature xmss_sign(SlhDsaNode{N} m, SlhDsaPrivateKey{N << 3} privkey, uint128 index, SlhDsaAddress* adrs)
{
	XmssSignature sig;
	for (uint j = 0; j < PARAMS.hp; j++)
	{
		uint128 k = (uint128)math::floor(index / math::pow(2, j)) ^ 1;
		sig.auth_path[j] = xmss_node(privkey, k, j, adrs);
	}
	adrs.set_type_and_clear(WOTS_HASH);
	adrs.set_key_pair_address(index);
	sig.wots = wots_sign(m, privkey, adrs);
	return sig;
}

<*
 Algorithm 11.
*>
fn SlhDsaNode{N} xmss_pk_from_sig(uint128 index, XmssSignature sig, SlhDsaNode{N} m, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress* adrs)
{
	SlhDsaNode{N}[2] nodes;
	adrs.set_type_and_clear(WOTS_HASH);
	adrs.set_key_pair_address(index);
	nodes[0] = wots_pk_from_sig(sig.wots, m, pubkey, adrs);
	adrs.set_type_and_clear(TREE);
	adrs.set_tree_index(index);
	for (uint k = 0; k < PARAMS.hp; k++)
	{
		adrs.set_tree_height((uint128)k + 1);
		if ((uint128)math::floor(index / math::pow(2, k)) % 2 == 0)
		{
			adrs.set_tree_index(adrs.get_tree_index() / 2);
			nodes[1] = h(pubkey.seed, adrs, (SlhDsaNode{N}[2]){ nodes[0], sig.auth_path[k] });
		}
		else
		{
			adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
			nodes[1] = h(pubkey.seed, adrs, (SlhDsaNode{N}[2]){ sig.auth_path[k], nodes[0] });
		}
		nodes[0] = nodes[1];
	}
	return nodes[0];
}


// ============================================================================
// ============================================================================
// ============================================================================
// The Hypertree (Section 7) - related algorithms, constants, helpers, et al.
//

<* A hypertree signature consists of `d` XMSS signatures, from lowest to uppermost. *>
const uint HYPERTREE_SIGNATURE_LEN = (PARAMS.h + (PARAMS.d * WOTS_LEN)) * N;   // alt: PARAMS.d * XmssSignature.sizeof

struct HypertreeSignature
{
	XmssSignature[PARAMS.d] xmss_sigs;
}
// TODO: Investigate why this doesn't work
// fn bool HypertreeSignature.eq(&self, HypertreeSignature other) @operator(==) => member_eq(*self, other);
fn bool HypertreeSignature.eq(&self, HypertreeSignature other) @operator(==)
{
	foreach (i, &s : self.xmss_sigs) if (*s != other.xmss_sigs[i]) return false;
	return true;
}

<*
 Algorithm 12.
*>
fn HypertreeSignature ht_sign(SlhDsaNode{N} m, SlhDsaPrivateKey{N << 3} privkey, uint128 index_tree, uint128 index_leaf)
{
	HypertreeSignature sig;
	SlhDsaAddress adrs;
	adrs.set_tree_address(index_tree);
	sig.xmss_sigs[0] = xmss_sign(m, privkey, index_leaf, &adrs);
	SlhDsaNode{N} root = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[0], m, privkey.pub, &adrs);
	for (uint j = 1; j < PARAMS.d; j++)
	{
		index_leaf = index_tree % (uint128)math::pow(2, PARAMS.hp);
		index_tree >>= PARAMS.hp;
		adrs.set_layer_address(j);
		adrs.set_tree_address(index_tree);
		sig.xmss_sigs[j] = xmss_sign(root, privkey, index_leaf, &adrs);
		if (j < PARAMS.d - 1)
		{
			root = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[j], root, privkey.pub, &adrs);
		}
	}
	return sig;
}

<*
 Algorithm 13.
*>
fn bool ht_verify(SlhDsaNode{N} m, HypertreeSignature sig, SlhDsaPublicKey{N << 3} pubkey, uint128 index_tree, uint128 index_leaf)
{
	SlhDsaAddress adrs;
	adrs.set_tree_address(index_tree);
	SlhDsaNode{N} node = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[0], m, pubkey, &adrs);
	for (uint j = 1; j < PARAMS.d; j++)
	{
		index_leaf = index_tree % (uint128)math::pow(2, PARAMS.hp);
		index_tree >>= PARAMS.hp;
		adrs.set_layer_address(j);
		adrs.set_tree_address(index_tree);
		node = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[j], node, pubkey, &adrs);
	}
	return node == pubkey.root;
}


// ============================================================================
// ============================================================================
// ============================================================================
// FORS (Section 8) - related algorithms, constants, helpers, et al.
//

// const uint FORS_K = PARAMS.k;
// const uint FORS_T = (uint)math::pow(2, (int)PARAMS.a); // TODO: not a constant value - is this even necessary?
const uint FORS_DIGEST_LEN = @ct_ceil((PARAMS.a * PARAMS.k) / 8.0);

struct ForsPrivateSet
{
	SlhDsaNode{N} private_key;
	SlhDsaNode{N}[PARAMS.a] auth_path;
}
fn bool ForsPrivateSet.eq(&self, ForsPrivateSet other) @operator(==) => member_eq(*self, other);

struct ForsSignature
{
	ForsPrivateSet[PARAMS.k] keys;
}
// TODO: Investigate why this doesn't work
// fn bool ForsSignature.eq(&self, ForsSignature other) @operator(==) => member_eq(*self, other);
fn bool ForsSignature.eq(&self, ForsSignature other) @operator(==)
{
	foreach (i, &k : self.keys) if (*k != other.keys[i]) return false;
	return true;
}

<*
 Algorithm 14.
*>
fn SlhDsaNode{N} fors_sk_gen(SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress* adrs, uint128 index)
{
	SlhDsaAddress sk_adrs = *adrs;
	sk_adrs.set_type_and_clear(FORS_PRF);
	sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	sk_adrs.set_tree_index(index);
	return prf(privkey.pub.seed, privkey.seed, &sk_adrs);
}

<*
 Algorithm 15.
*>
fn SlhDsaNode{N} fors_node(SlhDsaPrivateKey{N << 3} privkey, uint128 node_index, uint128 node_height, SlhDsaAddress* adrs)
{
	if (node_height == 0)
	{
		SlhDsaNode{N} sk = fors_sk_gen(privkey, adrs, node_index);
		adrs.set_tree_height(0);
		adrs.set_tree_index(node_index);
		return f(privkey.pub.seed, adrs, sk);
	}
	SlhDsaNode{N} left  = fors_node(privkey, 2 * node_index, node_height - 1, adrs);
	SlhDsaNode{N} right = fors_node(privkey, 2 * node_index + 1, node_height - 1, adrs);
	adrs.set_tree_height(node_height);
	adrs.set_tree_index(node_index);
	return h(privkey.pub.seed, adrs, (SlhDsaNode{N}[2]){ left, right });
}

<*
 Algorithm 16.
*>
fn ForsSignature fors_sign(char[FORS_DIGEST_LEN] md, SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress* adrs)
{
	ForsSignature sig;
	uint128[PARAMS.k] indices = base_2b(md[..], PARAMS.a, PARAMS.k);
	for (uint i = 0; i < PARAMS.k; i++)
	{
		sig.keys[i].private_key = fors_sk_gen(privkey, adrs, i * (uint128)math::pow(2, PARAMS.a) + indices[i]);
		for (uint j = 0; j < PARAMS.a; j++)
		{
			uint128 s = (uint128)math::floor(indices[i] / (double)math::pow(2, j)) ^ 1;
			sig.keys[i].auth_path[j] = fors_node(privkey, i * (uint128)math::pow(2, PARAMS.a - j) + s, j, adrs);
		}
	}
	return sig;
}

<*
 Algorithm 17.
*>
fn SlhDsaNode{N} fors_pk_from_sig(ForsSignature sig, char[FORS_DIGEST_LEN] md, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress* adrs)
{
	SlhDsaNode{N}[PARAMS.k] roots;
	SlhDsaNode{N}[2] nodes;
	uint128[PARAMS.k] indices = base_2b(md[..], PARAMS.a, PARAMS.k);
	for (uint i = 0; i < PARAMS.k; i++)
	{
		adrs.set_tree_height(0);
		adrs.set_tree_index(i * (uint128)math::pow(2, PARAMS.a) + indices[i]);
		nodes[0] = f(pubkey.seed, adrs, sig.keys[i].private_key);
		for (uint j = 0; j < PARAMS.a; j++)
		{
			adrs.set_tree_height((uint128)j + 1);
			if ((uint128)math::floor(indices[i] / (double)math::pow(2, j)) % 2 == 0)
			{
				adrs.set_tree_index(adrs.get_tree_index() / 2);
				nodes[1] = h(pubkey.seed, adrs, (SlhDsaNode{N}[2]){ nodes[0], sig.keys[i].auth_path[j] });
			}
			else
			{
				adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
				nodes[1] = h(pubkey.seed, adrs, (SlhDsaNode{N}[2]){ sig.keys[i].auth_path[j], nodes[0] });
			}
			nodes[0] = nodes[1];
		}
		roots[i] = nodes[0];
	}
	SlhDsaAddress fors_pk_adrs = *adrs;
	fors_pk_adrs.set_type_and_clear(FORS_ROOTS);
	fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	return t(pubkey.seed, &fors_pk_adrs, @as_char_view(roots));
}


// ============================================================================
// ============================================================================
// ============================================================================
// INTERNAL FUNCTIONS (Section 9)
//

import std::collections::pair;   // TODO: do not return a Pair - this is temporary while refactoring

struct SlhDsaSignature
{
	SlhDsaNode{N} randomness;
	ForsSignature fors_sig;
	HypertreeSignature ht_sig;
}
fn bool SlhDsaSignature.eq(&self, SlhDsaSignature other) @operator(==) => member_eq(*self, other);

<*
 Algorithm 18.
*>
fn SlhDsaKeyPair{N << 3} keygen_internal(SlhDsaNode{N} sk_seed, SlhDsaNode{N} sk_prf, SlhDsaNode{N} pk_seed)
{
	SlhDsaPublicKey{N << 3} pubkey = { .seed = pk_seed };
	SlhDsaPrivateKey{N << 3} privkey = { .seed = sk_seed, .prf = sk_prf };
	SlhDsaAddress adrs;
	adrs.set_layer_address(PARAMS.d - 1);
	pubkey.root = xmss_node(privkey, 0, PARAMS.hp, &adrs);
	privkey.pub = pubkey;
	return { pubkey, privkey };
}

const uint DIGEST_SPAN = @ct_ceil((PARAMS.k * PARAMS.a) / 8.0);
const uint TREE_SPAN = @ct_ceil((PARAMS.h - PARAMS.h / PARAMS.d) / 8.0);
const uint LEAF_SPAN = @ct_ceil(PARAMS.h / (8.0 * PARAMS.d));

<*
 Algorithm 19.

 @require !hedged || (hedged && addrnd != {}) : "When using the hedged variant of SLH-DSA, you _must_ generate `N` random bytes for `addrnd`."
*>
fn SlhDsaSignature sign_internal(char[] message, SlhDsaPrivateKey{N << 3} privkey, SlhDsaNode{N} addrnd = {}, bool hedged = true)
{
	SlhDsaSignature sig;
	SlhDsaAddress adrs;
	if (!hedged) addrnd = privkey.pub.seed;   // consider 'addrnd' an alias for 'opt_rand' in this function
	sig.randomness = prf_msg(privkey.prf, addrnd, message);
	char[PARAMS.m] digest = hash_msg(sig.randomness, privkey.pub, message);
	char[] md = digest[:DIGEST_SPAN];
	uint128 index_tree = to_int(digest[DIGEST_SPAN:TREE_SPAN], TREE_SPAN) % (uint128)math::pow(2, PARAMS.h - PARAMS.h / PARAMS.d);
	uint128 index_leaf = to_int(digest[(DIGEST_SPAN + TREE_SPAN):LEAF_SPAN], LEAF_SPAN) % (uint128)math::pow(2, PARAMS.h / PARAMS.d);
	adrs.set_tree_address(index_tree);
	adrs.set_type_and_clear(FORS_TREE);
	adrs.set_key_pair_address(index_leaf);
	sig.fors_sig = fors_sign(md[:DIGEST_SPAN], privkey, &adrs);
	SlhDsaNode{N} pk_fors = fors_pk_from_sig(sig.fors_sig, md[:DIGEST_SPAN], privkey.pub, &adrs);
	sig.ht_sig = ht_sign(pk_fors, privkey, index_tree, index_leaf);
	return sig;
}

<*
 Algorithm 20.
*>
fn bool verify_internal(char[] message, SlhDsaSignature sig, SlhDsaPublicKey{N << 3} pubkey)
{
	if (message.len != PARAMS.signature_len) return false;
	SlhDsaAddress adrs;
	char[PARAMS.m] digest = hash_msg(sig.randomness, pubkey, message);
	char[] md = digest[:DIGEST_SPAN];
	uint128 index_tree = to_int(digest[DIGEST_SPAN:TREE_SPAN], TREE_SPAN) % (uint128)math::pow(2, PARAMS.h - PARAMS.h / PARAMS.d);
	uint128 index_leaf = to_int(digest[(DIGEST_SPAN + TREE_SPAN):LEAF_SPAN], LEAF_SPAN) % (uint128)math::pow(2, PARAMS.h / PARAMS.d);
	adrs.set_tree_address(index_tree);
	adrs.set_type_and_clear(FORS_TREE);
	adrs.set_key_pair_address(index_leaf);
	SlhDsaNode{N} pk_fors = fors_pk_from_sig(sig.fors_sig, md[:DIGEST_SPAN], pubkey, &adrs);
	return ht_verify(pk_fors, sig.ht_sig, pubkey, index_tree, index_leaf);
}
