// Copyright (c) 2026 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// This implementation is based on FIPS-205 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
//
module std::crypto::slh_dsa @private;

import std::math;

<*
 Algorithm 2.

 @require x.len == $n : "The input byte-string `x` is not a suficient length."
*>
macro to_int(x, $n)
{
	uint128 total;
	for (usz i = 0; i < $n; i++) total = (total * 256) + x[i];
	$switch:
		$case $n == 1: return (char)total;
		$case $n == 2: return (ushort)total;
		$case $n <= 4: return (uint)total;
		$case $n <= 8: return (ulong)total;
		$case $n <= 16: return total;
		$default: $error "Invalid 'n' constraint on Algorithm 2 (`to_int`)."
	$endswitch
}

<*
 Algorithm 3.
*>
macro char[*] to_byte(x, $n)
{
	char[$n] res;
	var total = x;
	for (usz i = 0; i < $n; i++)
	{
		res[$n - 1 - i] = total % 256u;
		total >>= 8;
	}
	return res;
}

<*
 Algorithm 4.

 @require byte_string.len >= math::ceil(($out_len * $b) / 8.0) : "Input byte string length is insufficient."
*>
macro uint[*] base_2b(char[] byte_string, usz $b, usz $out_len)
{
	uint[$out_len] res;
	usz in, bits, total;
	for (usz out = 0; out < out_len; out++)
	{
		while (bits < $b)
		{
			total = (total << 8) + byte_string[in];
			in++;
			bits += 8;
		}
		bits -= $b;
		res[out] = (total >> bits) % math::pow(2, b);
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
	usz n;
	usz h;   // the total height of the hypertree (d * hp)
	usz d;   // depth of XMSS trees within the SLH-DSA hypertree
	usz hp;   // height of each Merkle Tree comprising a single XMSS signature
	usz a;
	usz k;
	usz lg_w;
	usz m;
	usz category;
	usz pubkey_len;
	usz signature_len;
}
const SlhDsaParameters[] PARAMS = {
	{ 16, 63,  7, 9, 12, 14, 4, 30, 1, 32,  7_856 },   // 128s
	{ 16, 66, 22, 3,  6, 33, 4, 34, 1, 32, 17_088 },   // 128f
	{ 24, 63,  7, 9, 14, 17, 4, 39, 3, 48, 16_224 },   // 192s
	{ 24, 66, 22, 3,  8, 33, 4, 42, 3, 48, 35_664 },   // 192f
	{ 32, 64,  8, 8, 14, 22, 4, 47, 5, 64, 29_792 },   // 256s
	{ 32, 68, 17, 4,  9, 35, 4, 49, 5, 64, 49_856 },   // 256f
};

macro SlhDsaParameters select_params($strength, SlhDsaMode $mode) @const
{
	return PARAMS[($strength / 8 - 2) * 2 + $mode.ordinal];
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

struct SlhDsaAddress @align(uint.sizeof) @packed
{
	uint layer;   // height of an XMSS tree within the hypertree
	uint[3] tree;   // position of an XMSS tree within a layer of the hypertree
	SlhDsaAddressType type;   // use-case-dependent type of address
	union
	{
		char[12] raw;
		WotsPlusHashAddress wots;
	}
}
fn bool SlhDsaAddress.eq(&self, SlhDsaAddress other) @operator(==) => @as_char_view(*self) == @as_char_view(other);

fn void SlhDsaAddress.set_layer_address(&self, uint l) => @as_char_view(self.layer)[..] = to_byte(l, uint.sizeof)[..];
fn void SlhDsaAddress.set_tree_address(&self, uint128 t) => @as_char_view(self.tree)[..] = to_byte(t, 12)[..];
fn void SlhDsaAddress.set_type_and_clear(&self, SlhDsaAddressType y)
{
	mem::zero_volatile(@as_char_view(*self)[16..]);
	@as_char_view(self.type)[..] = to_byte(y, uint.sizeof);
}
fn void SlhDsaAddress.set_key_pair_address(&self, uint i) => @as_char_view(self.wots.key_pair)[..] = to_byte(i, uint.sizeof)[..];
fn void SlhDsaAddress.set_chain_address(&self, uint i) => @as_char_view(self.wots.chain)[..] = to_byte(i, uint.sizeof)[..];
macro SlhDsaAddress.set_tree_height(&self, uint i) => self.set_chain_address(i);
fn void SlhDsaAddress.set_hash_address(&self, uint i) => @as_char_view(self.wots.hash)[..] = to_byte(i, uint.sizeof)[..];
macro SlhDsaAddress.set_tree_index(&self, uint i) => self.set_hash_address(i);
fn uint SlhDsaAddress.get_key_pair_address(&self) => to_int(@as_char_view(self.wots.key_pair), uint.sizeof);
fn uint SlhDsaAddress.get_tree_index(&self) => to_int(@as_char_view(self.wots.hash), uint.sizeof);


module std::crypto::slh_dsa;

import std::crypto::entropy, std::collections::pair;
import std::hash::sha256, std::hash::sha512, std::crypto::shake;

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
 See Section 9.1 of FIPS-205.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
*>
struct SlhDsaPublicKey <N>
{
	char[N >> 3] root;
	char[N >> 3] seed;
}
fn bool SlhDsaPublicKey.eq(&self, SlhDsaPublicKey{N} other) @operator(==) => member_eq(*self, other);

<*
 See Section 9.1 of FIPS-205.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
*>
struct SlhDsaPrivateKey <N>
{
	char[N >> 3] seed;   // used to generate all WOTS+ and FORS pk elements
	char[N >> 3] prf;   // used to generate a randomization value for randomized message hashing
	SlhDsaPublicKey{N} pub;
}
fn bool SlhDsaPrivateKey.eq(&self, SlhDsaPrivateKey{N} other) @operator(==) => member_eq(*self, other);

// TODO: Refactor and remove macros here
<*
 Algorithm 21.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
*>
macro Pair{SlhDsaPublicKey{N}, SlhDsaPrivateKey{N}}? keygen(SlhDsaHashType $type = SHAKE, SlhDsaMode $mode = FAST) <N>
{
	SlhDsaPrivateKey{N} privkey;
	SlhDsaPublicKey{N} pubkey;
	entropy::fill(privkey.root[..])!;
	entropy::fill(privkey.prf[..])!;
	entropy::fill(pubkey.seed[..])!;
	return keygen_internal{N >> 3, $type, $mode}(privkey.seed, privkey.prf, pubkey.seed);
}

<*
 Algorithm 22.

 @require @in(N, 128, 192, 256) : "The `N` size must be set to the appropriate supported key size: 128, 192, or 256."
 @require context.len <= 255 : "The `context` byte-string has a maximum length of 255 bytes."

 @return? SECURE_RANDOM_UNAVAILABLE : "The cryptographically-secure PRNG is not available. You may need to set `hedged` to `false` to continue."
*>
macro char[]? sign(Allocator allocator, SlhDsaPrivateKey{N} privkey, char[] message, char[] context = {},
	bool hedged = true, SlhDsaHashType $type = SHAKE, SlhDsaMode $mode = FAST) <N> => @pool()
{
	var $SigType = $typeof(SlhDsaSignature{N >> 3, $type, $mode});
	char[] res = alloc::new_array(allocator, char, $SigType.sizeof);
	char[N] addrnd;
	if (hedged) entropy::fill(addrnd[..])!;
	char[] message_p = alloc::alloc_array(tmem, char, 1 + 1 + context.len + message.len);
	message_p[0] = 0;
	message_p[1] = context.len;
	message_p[2 : context.len] = context[..];
	message_p[2 + context.len ..] = message[..];
	$SigType signature = sign_internal{N >> 3, $type, $mode}(message, privkey, addrnd: addrnd, hedged: hedged);
	res[..] = @as_char_view(signature)[..];
	return res;
}

enum SlhDsaPreHashType : (BEUint128 oid)
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

 @return? SECURE_RANDOM_UNAVAILABLE : "The cryptographically-secure PRNG is not available. You may need to set `hedged` to `false` to continue."
 @return? NOT_FOUND : "The pre-hash type is not valid."
*>
macro char[]? hash_sign(Allocator allocator, SlhDsaPrivateKey{N} privkey, char[] message, SlhDsaPreHashType pre_hash,
	char[] context = {}, bool hedged = true, SlhDsaHashType $type = SHAKE, SlhDsaMode $mode = FAST) <N> => @pool()
{
	var $SigType = $typeof(SlhDsaSignature{N >> 3, $type, $mode});
	char[64] tmp_hash;
	char[] hash;
	char[N] addrnd;
	if (hedged) entropy::fill(addrnd[..])!;
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
	message_p[2 + context.len : 11] = @as_char_view(pre_hash.oid)[^12..];
	message_p[2 + context.len + 11 ..] = hash[..];
	$SigType signature = sign_internal{N >> 3, $type, $mode}(hash, privkey, addrnd: addrnd, hedged: hedged);
	res[..] = @as_char_view(signature)[..];
	return res;
}


<*
 NOTE: Per specification requirements, a random number generator with a strength of _at least_ `8N` bits _must_ be used.

 @require @in(N, 16, 24, 32) : "The SLH-DSA 'n' value must be a supported integer length (16, 24, or 32 bytes)."
 @require $typeof(HASH_TYPE) == SlhDsaHashType : "`HASH_TYPE` must be a valid value from the `SlhDsaHashType` enum."
 @require $typeof(MODE) == SlhDsaMode : "`MODE` must be a valid value from the `SlhDsaMode` enum."
*>
module std::crypto::slh_dsa <N, HASH_TYPE, MODE> @private;

import std::crypto::shake;

<* The compile-time parameter set selected based on the generic module parameters. *>
const PARAMS = select_params(N, MODE);

<*
 Used to generate the secret values for WOTS+ and FORS private keys.
*>
fn char[N] prf(char[N] pubkey_seed, char[N] privkey_seed, SlhDsaAddress adrs)
{
	char[N] result;
	$if HASH_TYPE == SHAKE:
		Shake256 s @noinit;
		s.init();
		s.update(pubkey_seed);
		s.update(@as_char_view(adrs));
		s.update(privkey_seed);
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
fn char[N] prf_msg(char[N] privkey_prf, char[N] opt_rand, char[] message)
{
	char[N] result;
	$if HASH_TYPE == SHAKE:
		Shake256 s @noinit;
		s.init();
		s.update(privkey_prf[..]);
		s.update(opt_rand[..]);
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
fn char[PARAMS.m] hash_msg(char[N] randomizer, SlhDsaPublicKey{N << 3} pubkey, char[] message)
{
	char[PARAMS.m] result;
	$if HASH_TYPE == SHAKE:
		Shake256 s @noinit;
		s.init();
		s.update(randomizer);
		s.update(pubkey.seed[..]);
		s.update(pubkey.root[..]);
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
fn char[N] _simple_shake(char[N] pubkey_seed, SlhDsaAddress adrs, char[] message)
{
	char[N] res;
	Shake256 s @noinit;
	s.update(pubkey_seed[..]);
	s.update(@as_char_view(adrs));
	s.update(message);
	s.final(res[..]);
	return res;
}

<*
 Hash function that maps an L-byte message to an N-byte message.
*>
fn char[N] t(char[N] pubkey_seed, SlhDsaAddress adrs, char[] message)
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
fn char[N] h(char[N] pubkey_seed, SlhDsaAddress adrs, char[2 * N] message)
{
	$if HASH_TYPE == SHAKE:
		return _simple_shake(pubkey_seed, adrs, message[..]);
	$else
		return NOT_IMPLEMENTED~!!;
	$endif
}

<*
 Hash function that maps an N-byte input to a different N-byte output.
*>
fn char[N] f(char[N] pubkey_seed, SlhDsaAddress adrs, char[N] message)
{
	$if HASH_TYPE == SHAKE:
		return _simple_shake(pubkey_seed, adrs, message[..]);
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
const usz WOTS_LEN1 = 2 * N;
const usz WOTS_LEN2 = 3;
const usz WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;
const usz WOTS_LG_W = PARAMS.lg_w;
const usz WOTS_W = 16;

<*
 Algorithm 5.
*>
fn char[N] chain(char[N] x, usz i, usz s, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress adrs) => @pool()
{
	char[N] tmp = x;
	for (uint j = i; j < i + s; j++)
	{
		adrs.set_hash_address(j);
		tmp = f(pubkey.seed, adrs, tmp);
	}
	return tmp;
}

<*
 Algorithm 6.
*>
fn char[N] wots_pk_gen(SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress adrs)
{
	char[WOTS_LEN * N] chains;
	SlhDsaAddress sk_adrs = adrs;
	sk_adrs.set_type_and_clear(WOTS_PRF);
	sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	for (usz i = 0; i < WOTS_LEN; i++)
	{
		sk_adrs.set_chain_address(i);
		char[N] sk = prf(privkey.pub.seed, privkey.seed, sk_adrs);
		adrs.set_chain_address(i);
		chains[i] = chain(sk, 0, WOTS_W - 1, privkey.pub.seed, *adrs);
	}
	SlhDsaAddress wots_pk_adrs = adrs;
	wots_pk_adrs.set_type_and_clear(WOTS_PK);
	wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	return t(privkey.pub.seed, wots_pk_adrs, chains[..]);
}

<*
 Algorithm 7.
*>
fn char[WOTS_LEN * N] wots_sign(char[N] m, SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress adrs)
{
	char[WOTS_LEN * N] sig;
	uint csum;
	uint[WOTS_LEN] msg;
	msg[:WOTS_LEN1] = base_2b(m, WOTS_LG_W, WOTS_LEN1)[..];
	for (usz i = 0; i < WOTS_LEN1; i++) csum += WOTS_W - 1 - msg[i];
	csum <<= 4; // this comes from the following formula: (8 - ((WOTS_LEN2 * WOTS_LG_W) % 8)) % 8
	msg[WOTS_LEN1:WOTS_LEN2] = base_2b(to_byte(csum, 2), WOTS_LG_W, WOTS_LEN2)[..];   // again, simplified
	SlhDsaAddress sk_adrs = adrs;
	sk_adrs.set_type_and_clear(WOTS_PRF);
	sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	for (usz i = 0; i < WOTS_LEN; i++)
	{
		sk_adrs.set_chain_address(i);
		char[N] sk = prf(privkey.pub.seed, privkey.seed, sk_adrs);
		adrs.set_chain_address(i);
		sig[(i * N):N] = chain(sk, 0, msg[i], privkey.pub.seed, adrs);
	}
	return sig;
}

<*
 Algorithm 8.
*>
fn char[N] wots_pk_from_sig(char[WOTS_LEN * N] sig, char[N] m, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress adrs)
{
	char[WOTS_LEN * N] tmp;
	uint csum;
	uint[WOTS_LEN] msg;
	msg[:WOTS_LEN] = base_2b(m, WOTS_LG_W, WOTS_LEN1)[..];
	for (usz i = 0; i < WOTS_LEN1; i++) csum += WOTS_W - 1 - msg[i];
	csum <<= 4;
	msg[WOTS_LEN1:WOTS_LEN2] = base_2b(to_byte(csum, 2), WOTS_LG_W, WOTS_LEN2)[..];
	for (usz i = 0; i < WOTS_LEN; i++)
	{
		adrs.set_chain_address(i);
		tmp[(i * N):N] = chain(sig[(i * N):N], msg[i], WOTS_W - 1 - msg[i], pubkey.seed, adrs);
	}
	SlhDsaAddress wots_pk_adrs = adrs;
	wots_pk_adrs.set_type_and_clear(WOTS_PK);
	wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	return t(pubkey.seed, wots_pk_adrs, tmp[..]);
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
const usz XMSS_SIGNATURE_LEN = (WOTS_LEN + XMSS_HEIGHT) * N;

<* The height of a single XMSS Merkle Tree. *>
const usz XMSS_HEIGHT = PARAMS.hp;

struct XmssSignature @packed
{
	char[WOTS_LEN * N] wots;
	char[XMSS_HEIGHT * N] auth_path;
}
fn bool XmssSignature.eq(&self, XmssSignature other) @operator(==) => member_eq(*self, other);

<*
 Algorithm 9.
*>
fn char[N] xmss_node(SlhDsaPrivateKey{N << 3} privkey, usz node_index, usz node_height, SlhDsaAddress adrs)
{
	if (z == 0)
	{
		adrs.set_type_and_clear(WOTS_HASH);
		adrs.set_key_pair_address(i);
		return wots_pk_gen(privkey, adrs);
	}
	char[N] left  = xmss_node(privkey.seed, 2 * node_index, node_height - 1, privkey.pub.seed, adrs);
	char[N] right = xmss_node(privkey.seed, 2 * node_index + 1, node_height - 1, privkey.pub.seed, adrs);
	adrs.set_type_and_clear(TREE);
	adrs.set_tree_height(node_height);
	adrs.set_tree_index(node_index);
	return h(privkey.pub.seed, *adrs, char[2 * N]{ ...left, ...right });
}

<*
 Algorithm 10.
*>
fn XmssSignature xmss_sign(char[N] m, SlhDsaPrivateKey{N << 3} privkey, usz index, SlhDsaAddress adrs)
{
	XmssSignature sig @noinit;
	for (usz j = 0; j < XMSS_HEIGHT; j++)
	{
		usz k = (usz)math::floor(index / math::pow(2, j)) ^ 1;
		sig.auth_path[j * N : N] = xmss_node(privkey.seed, k, j, privkey.pub.seed, adrs);
	}
	adrs.set_type_and_clear(WOTS_HASH);
	adrs.set_key_pair_address(index);
	sig.wots = wots_sign(m, privkey, adrs);
	return sig;
}

<*
 Algorithm 11.
*>
fn char[N] xmss_pk_from_sig(usz index, XmssSignature sig, char[N] m, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress adrs)
{
	char[2 * N] nodes;
	adrs.set_type_and_clear(WOTS_HASH);
	adrs.set_key_pair_address(index);
	nodes[0] = wots_pk_from_sig(sig.wots, m, pubkey.seed, adrs);
	adrs.set_type_and_clear(TREE);
	adrs.set_tree_index(index);
	for (usz k = 0; k < XMSS_HEIGHT; k++)
	{
		adrs.set_tree_height(k + 1);
		if ((uint)math::floor(index / math::pow(2, k)) % 2 == 0)
		{
			adrs.set_tree_index(adrs.get_tree_index() / 2);
			nodes[1] = h(pubkey.seed, adrs, (char[2 * N]){ ...nodes[0], ...sig.auth_path[(k * N) : N] });
		}
		else
		{
			adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
			nodes[1] = h(pubkey.seed, adrs, (char[2 * N]){ ...sig.auth_path[(k * N) : N], ...nodes[0] });
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
const usz HYPERTREE_SIGNATURE_LEN = (PARAMS.h + (PARAMS.d * WOTS_LEN)) * N;   // alt: PARAMS.d * XmssSignature.sizeof

struct HypertreeSignature
{
	XmssSignature[PARAMS.d] xmss_sigs;
}
fn bool HypertreeSignature.eq(&self, HypertreeSignature other) @operator(==) => member_eq(*self, other);

<*
 Algorithm 12.
*>
fn HypertreeSignature ht_sign(char[N] m, SlhDsaPrivateKey{N << 3} privkey, usz index_tree, usz index_leaf)
{
	HypertreeSignature sig;
	SlhDsaAddress adrs;
	adrs.set_tree_address(index_tree);
	sig.xmss_sigs[0] = xmss_sign(m, privkey, index_leaf, adrs);
	char[N] root = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[0], m, privkey.pub, adrs);
	for (usz j = 1; j < PARAMS.d; j++)
	{
		index_leaf = index_tree % math::pow(2, XMSS_HEIGHT);
		index_tree = index_tree >> XMSS_HEIGHT;
		adrs.set_layer_address(j);
		adrs.set_tree_address(index_tree);
		sig.xmss_sigs[j] = xmss_sign(root, privkey, index_leaf, adrs);
		if (j < PARAMS.d - 1)
		{
			root = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[j], root, privkey.pub, adrs);
		}
	}
	return sig;
}

<*
 Algorithm 13.
*>
fn bool ht_verify(char[N] m, HypertreeSignature sig, SlhDsaPublicKey{N << 3} pubkey, usz index_tree, usz index_leaf)
{
	SlhDsaAddress adrs;
	adrs.set_tree_address(index_tree);
	char[N] node = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[0], m, pubkey, adrs);
	for (usz j = 1; j < PARAMS.d; j++)
	{
		index_leaf = index_tree % math::pow(2, XMSS_HEIGHT);
		index_tree = index_tree >> XMSS_HEIGHT;
		adrs.set_layer_address(j);
		adrs.set_tree_address(index_tree);
		node = xmss_pk_from_sig(index_leaf, sig.xmss_sigs[j], node, pubkey, adrs);
	}
	return node == pubkey.root;
}


// ============================================================================
// ============================================================================
// ============================================================================
// FORS (Section 8) - related algorithms, constants, helpers, et al.
//

const usz FORS_K = PARAMS.k;
const usz FORS_T = math::pow(2, PARAMS.a);
const usz FORS_DIGEST_LEN = (PARAMS.a * PARAMS.k) >> 3;

struct ForsPrivateSet
{
	char[N] private_key;
	char[PARAMS.a * N] auth_path;
}
fn bool ForsPrivateSet.eq(&self, ForsPrivateSet other) @operator(==) => member_eq(*self, other);

struct ForsSignature
{
	ForsPrivateSet[PARAMS.k] keys;
}
fn bool ForsSignature.eq(&self, ForsSignature other) @operator(==) => member_eq(*self, other);

<*
 Algorithm 14.
*>
fn char[N] fors_sk_gen(SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress adrs, usz index)
{
	SlhDsaAddress sk_adrs = adrs;
	sk_adrs.set_type_and_clear(FORS_PRF);
	sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	sk_adrs.set_tree_index(index);
	return prf(privkey.pub.seed, privkey.seed, sk_adrs);
}

<*
 Algorithm 15.
*>
fn char[N] fors_node(SlhDsaPrivateKey{N << 3} privkey, usz node_index, usz node_height, SlhDsaAddress adrs)
{
	if (node_height == 0)
	{
		char[N] sk = fors_sk_gen(privkey, adrs, node_index);
		adrs.set_tree_height(0);
		adrs.set_tree_index(node_index);
		return f(privkey.pub.seed, adrs, sk);
	}
	char[N] left  = fors_node(privkey, 2 * node_index, node_height - 1, adrs);
	char[N] right = fors_node(privkey, 2 * node_index + 1, node_height - 1, adrs);
	adrs.set_tree_height(node_height);
	adrs.set_tree_index(node_index);
	return h(privkey.pub.seed, adrs, (char[2 * N]){ ...left, ...right });
}

<*
 Algorithm 16.
*>
fn ForsSignature fors_sign(char[FORS_DIGEST_LEN] md, SlhDsaPrivateKey{N << 3} privkey, SlhDsaAddress adrs)
{
	ForsSignature sig @noinit;
	uint[PARAMS.k] indices = base_2b(md, PARAMS.a, PARAMS.k);
	for (usz i = 0; i < PARAMS.k; i++)
	{
		sig.keys[i].private_key = fors_sk_gen(privkey, adrs, i * math::pow(2, PARAMS.a) + indices[i]);
		for (usz j = 0; j < PARAMS.a; j++)
		{
			usz s = (usz)math::floor(indices[i] / (double)math::pow(2, j)) ^ 1;
			sig.keys[i].auth_path[j] = fors_node(privkey, i * math::pow(2, PARAMS.a - j) + s, j, adrs);
		}
	}
	return sig;
}

<*
 Algorithm 17.
*>
fn char[N] fors_pk_from_sig(ForsSignature sig, char[FORS_DIGEST_LEN] md, SlhDsaPublicKey{N << 3} pubkey, SlhDsaAddress adrs)
{
	char[PARAMS.k * N] roots;
	char[2 * N] nodes;
	uint[PARAMS.k] indices = base_2b(md, PARAMS.a, PARAMS.k);
	for (usz i = 0; i < PARAMS.k; i++)
	{
		adrs.set_tree_height(0);
		adrs.set_tree_index(i * math::pow(2, PARAMS.a) + indices[i]);
		nodes[0] = f(pubkey.seed, adrs, sig.keys[i].private_key);
		for (usz j = 0; j < PARAMS.a; j++)
		{
			adrs.set_tree_height(j + 1);
			if ((usz)math::floor(indices[i] / (double)math::pow(2, j)) % 2 == 0)
			{
				adrs.set_tree_index(adrs.get_tree_index() / 2);
				nodes[1] = h(pubkey.seed, adrs, (char[2 * N]){ ...nodes[0], ...sig.keys[i].auth_path[j] });
			}
			else
			{
				adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
				nodes[1] = h(pubkey.seed, adrs, (char[2 * N]){ ...sig.keys[i].auth_path[j], ...nodes[0] });
			}
			nodes[0] = nodes[1];
		}
		roots[i] = nodes[0];
	}
	SlhDsaAddress fors_pk_adrs = adrs;
	fors_pk_adrs.set_type_and_clear(FORS_ROOTS);
	fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());
	return t(pubkey.seed, fors_pk_adrs, roots[..]);
}


// ============================================================================
// ============================================================================
// ============================================================================
// INTERNAL FUNCTIONS (Section 9)
//

import std::collections::pair;   // TODO: do not return a Pair - this is temporary while refactoring

struct SlhDsaSignature
{
	char[N] randomness;
	ForsSignature fors_sig;
	HypertreeSignature ht_sig;
}
fn bool SlhDsaSignature.eq(&self, SlhDsaSignature other) @operator(==) => member_eq(*self, other);

<*
 Algorithm 18.
*>
fn Pair{SlhDsaPublicKey{N << 3}, SlhDsaPrivateKey{N << 3}} keygen_internal(char[N] sk_seed, char[N] sk_prf, char[N] pk_seed)
{
	SlhDsaPublicKey{N << 3} pubkey = { .seed = pk_seed };
	SlhDsaPrivateKey{N << 3} privkey = { .seed = sk_seed, .prf = sk_prf };
	SlhDsaAddress adrs;
	adrs.set_layer_address(PARAMS.d - 1);
	pubkey.root = xmss_node(privkey, 0, PARAMS.hp, adrs);
	privkey.pub = pubkey;
	return { pubkey, privkey };
}

<*
 Algorithm 19.

 @require !hedged || (hedged && addrnd != {}) : "When using the hedged variant of SLH-DSA, you _must_ generate `N` random bytes for `addrnd`."
*>
fn SlhDsaSignature sign_internal(char[] message, SlhDsaPrivateKey{N << 3} privkey, char[N] addrnd = {}, bool hedged = true)
{
	// TODO: If math::ceil were @const, this could be compile-time
	static usz digest_span = (usz)math::ceil((PARAMS.k * PARAMS.a) / 8.0);
	static usz tree_span = (usz)math::ceil((PARAMS.h - PARAMS.h / PARAMS.d) / 8.0);
	static usz leaf_span = (usz)math::ceil(PARAMS.h / (8.0 * PARAMS.d));
	SlhDsaSignature sig;
	SlhDsaAddress adrs;
	if (!hedged) addrnd = privkey.pub.seed;   // consider 'addrnd' an alias for 'opt_rand' in this function
	sig.randomness = prf_msg(privkey.prf, addrnd, message);
	char[PARAMS.m] digest = hash_msg(self.randomness, privkey.pub, message);
	char[] md = digest[:digest_span];
	uint index_tree = to_int(digest[digest_span:tree_span], tree_span) % math::pow(2, PARAMS.h - PARAMS.h / PARAMS.d);
	uint index_tree = to_int(digest[(digest_span + tree_span):leaf_span], leaf_span) % math::pow(2, PARAMS.h / PARAMS.d);
	adrs.set_tree_address(index_tree);
	adrs.set_type_and_clear(FORS_TREE);
	adrs.set_key_pair_address(index_leaf);
	sig.fors_sig = fors_sign(md, privkey, adrs);
	char[N] pk_fors = fors_pk_from_sig(sig.fors_sig, md, privkey.pub, adrs);
	sig.ht_sig = ht_sign(pk_fors, privkey, index_tree, index_leaf);
	return sig;
}

<*
 Algorithm 20.
*>
fn bool verify_internal(char[] message, SlhDsaSignature sig, SlhDsaPublicKey{N << 3} pubkey)
{
	static usz digest_span = (usz)math::ceil((PARAMS.k * PARAMS.a) / 8.0);
	static usz tree_span = (usz)math::ceil((PARAMS.h - PARAMS.h / PARAMS.d) / 8.0);
	static usz leaf_span = (usz)math::ceil(PARAMS.h / (8.0 * PARAMS.d));
	SlhDsaAddress adrs;
	char[PARAMS.m] digest = hash_msg(sig.randomness, pubkey, message);
	uint index_tree = to_int(digest[digest_span:tree_span], tree_span) % math::pow(2, PARAMS.h - PARAMS.h / PARAMS.d);
	uint index_tree = to_int(digest[(digest_span + tree_span):leaf_span], leaf_span) % math::pow(2, PARAMS.h / PARAMS.d);
	adrs.set_tree_address(index_tree);
	adrs.set_type_and_clear(FORS_TREE);
	adrs.set_key_pair_address(index_leaf);
	char[N] pk_fors = fors_pk_from_sig(sig.fors_sig, md, pubkey, adrs);
	return ht_verify(pk_fors, sig.ht_sig, pubkey, index_tree, index_leaf);
}
