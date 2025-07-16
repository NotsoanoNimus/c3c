// Copyright (c) 2025 Zack Puhl <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
//
// Based on the FastLZ (LZ77) v0.5 compression tool: https://github.com/ariya/FastLZ
//   Also see: https://ariya.github.io/FastLZ/
//
//   Copyright (C) 2005-2020 Ariya Hidayat <ariya.hidayat@gmail.com>
//
//   Permission is hereby granted, free of charge, to any person obtaining a copy
//   of this software and associated documentation files (the "Software"), to deal
//   in the Software without restriction, including without limitation the rights
//   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//   copies of the Software, and to permit persons to whom the Software is
//   furnished to do so, subject to the following conditions:
//
//   The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//   THE SOFTWARE.
//
module std::compression::fastlz @private;


const MAX_COPY = 32;
const MAX_LENGTH = 256 + 8;
const MAX_L1_DISTANCE = 1 << 13;   // 8192
const MAX_L2_DISTANCE = (1 << 13) - 1;
const MAX_FAR_DISTANCE = (1 << 16) - 1 + MAX_L2_DISTANCE - 1;

const HASH_LOG = 13;
const HASH_SIZE = 1 << HASH_LOG;

macro ushort @hash(uint v) => (ushort)((v * 2_654_435_769) >> (32 - HASH_LOG)) & (HASH_SIZE - 1);

// Used as `if (@bound_check(condition)) return 0;`.
//   from C source:  if (UNLIKELY(!(condition))) return 0;
macro @bound_check(#expr) => @unlikely(!(#expr));

macro @maxcopy(char[] dst, char[] src) => dst[:MAX_COPY] = src[:MAX_COPY];
macro @smallcopy(char[] dst, char[] src, runs) => mem::copy(dst, src, runs);

macro isz @lzcmp(char* p, char* q, char* r)
{
	char* start = p;
	while (q < r) if (*p++ != *q++) break;
	return p - start;
}


fn char[] literals(isz runs, char[] src, char[] dst)
{
	for (; runs >= MAX_COPY; src = src[MAX_COPY:^MAX_COPY], dst = dst[MAX_COPY:^MAX_COPY], runs -= MAX_COPY)
	{
		dst[0] = MAX_COPY - 1;   // *dst++ = MAX_COPY - 1;
		dst = dst[1:^1];

		mem::copy(dst, src, MAX_COPY);
	}

	if (runs > 0)
	{
		dst[0] = (char)(runs - 1);
		dst = dst[1:^1];

		mem::copy(dst, src, runs);

		dst = dst[runs:^runs];
	}

	return dst;
}


fn char[] lz1_match(isz len, isz distance, char[] orig) @local @inline
{
	--distance;

	for (; @unlikely(len > MAX_LENGTH - 2); len -= MAX_LENGTH - 2, orig = orig[3:^3])
	{
		orig[0] = (char)((7 << 5) + (distance >> 8));
		orig[1] = (char)(MAX_LENGTH - 2 - 7 - 2);
		orig[2] = (char)distance;
	}

	if (len < 7)
	{
		orig[0] = (char)((len << 5) + (distance >> 8));
		orig[1] = (char)distance;
		orig = orig[2:^2];
	}
	else
	{
		orig[0] = (char)((7 << 5) + (distance >> 8));
		orig[1] = (char)len - 7;
		orig[2] = (char)distance;
		orig = orig[3:^3];
	}

	return orig;
}


fn usz? lz1_compress(char[] input, char[] output)
{
	char* o_anchor, ip, ip_start, ip_bound, ip_limit, anchor;
	isz[HASH_SIZE] htab;
	uint seq, hash;

	o_anchor = output.ptr;
	ip_start = ip = anchor = input.ptr;
	ip_bound = &input[^4];   // ip + length - 4;
	ip_limit = &input[^13];   // ip + length - 12 - 1;

	ip += 2;

	while OUTER: (@likely(ip < ip_limit))
	{
		char* ref;
		isz distance;
		uint cmp;

		do INNER:
		{
			seq = @unaligned_load(*(uint*)ip, 1) & 0x00FF_FFFF;
			hash = @hash(seq);

			ref = ip_start + htab[hash];
			htab[hash] = ip - ip_start;

			distance = ip - ref;
			cmp = @likely(distance < MAX_L1_DISTANCE) ? (@unaligned_load(*(uint*)ref, 1) & 0x00FF_FFFF) : 0x0100_0000;

			if (@unlikely(ip >= ip_limit)) break OUTER;

			++ip;
		} while (seq != cmp);

		--ip;

		if (@likely(ip > anchor)) output = literals(ip - anchor, anchor[:(usz)input.ptr + input.len - (usz)anchor], output);

		isz len = @lzcmp(ref + 3, ip + 3, ip_bound);
		output = lz1_match(len, distance, output);

		ip += len;

		seq = @unaligned_load(*(uint*)ip, 1);
		hash = @hash(seq & 0x00FF_FFFF);
		htab[hash] = ip++ - ip_start;

		seq >>= 8;
		hash = @hash(seq);
		htab[hash] = ip++ - ip_start;

		anchor = ip;
	}

	output = literals(input.ptr + input.len - anchor, anchor[:(usz)input.ptr + input.len - (usz)anchor], output);

	return (usz)(output.ptr - o_anchor);
}


fn usz? lz1_decompress(char[] input, char[] output)
{
	char* ip, ip_bound, ip_limit, op, op_limit;

	op = output.ptr;
	op_limit = &output[^1] + 1;

	ip = input.ptr;
	ip_limit = &input[^1] + 1;
	ip_bound = &input[^2];

	uint ctrl = *ip++ & 31;

	while (true)
	{
		if (ctrl >= 32)
		{
			uint len = (ctrl >> 5) - 1;
			char* ref = op - ((isz)(ctrl & 31) << 8) - 1;

			if (len == 7 - 1)
			{
				if (@bound_check(ip <= ip_bound)) return OUT_OF_BOUNDS?;
				len += *ip++;
			}

			ref -= *ip++;
			len += 3;

			if (@bound_check(op + len <= op_limit)) return OUT_OF_BOUNDS?;
			if (@bound_check(ref >= output.ptr)) return OUT_OF_BOUNDS?;

			mem::copy(op, ref, len);

			op += len;
		}
		else
		{
			++ctrl;

			if (@bound_check(op + ctrl <= op_limit)) return OUT_OF_BOUNDS?;
			if (@bound_check(ip + ctrl <= ip_limit)) return OUT_OF_BOUNDS?;

			mem::copy(op, ip, ctrl);

			ip += ctrl;
			op += ctrl;
		}

		if (@unlikely(ip > ip_bound)) break;
		ctrl = *ip++;
	}

	return (usz)(op - output.ptr);
}


fn char[] lz2_match(isz len, isz distance, char[] orig) @local @inline
{
	--distance;

	if (distance < MAX_L2_DISTANCE)
	{
		orig[0] = (char)((min(len, 7) << 5) + (distance >> 8));

		if (len < 7)
		{
			orig[1] = (char)distance;
		}
		else
		{
			for (orig = orig[1:^1], len -= 7; len >= 255; len -= 255)
			{
				orig[0] = 255;
				orig = orig[1:^1];
			}
			orig[0] = (char)len;
			orig[1] = (char)distance;
		}

		orig = orig[2:^2];
	}
	else
	{
		distance -= MAX_L2_DISTANCE;
		orig[0] = (char)(min(len, 7) << 5 + 31);

		if (len < 7)
		{
			orig[1] = 0xFF;
			orig[2] = (char)(distance >> 8);
			orig[3] = (char)distance;
		}
		else
		{
			for (orig = orig[1:^1], len -= 7; len >= 255; len -= 255)
			{
				orig[0] = 255;
				orig = orig[1:^1];
			}
			orig[0] = (char)len;
			orig[1] = 255;
			orig[2] = (char)(distance >> 8);
			orig[3] = (char)distance;
		}

		orig = orig[4:^4];
	}

	return orig;
}


fn usz? lz2_compress(char[] input, char[] output)
{
	char* o_anchor, ip, ip_start, ip_bound, ip_limit, anchor;
	isz[HASH_SIZE] htab;
	uint seq, hash;

	o_anchor = output.ptr;
	ip_start = ip = anchor = input.ptr;
	ip_bound = &input[^4];   // ip + length - 4;
	ip_limit = &input[^13];   // ip + length - 12 - 1;

	ip += 2;

	while (@likely(ip < ip_limit)) TODO: DO THE THING
}


fn usz? lz2_decompress(char[] input, char[] output)
{
	return 0;
}

  while (FASTLZ_LIKELY(ip < ip_limit)) {
    const uint8_t* ref;
    uint32_t distance, cmp;

    /* find potential match */
    do {
      seq = flz_readu32(ip) & 0xffffff;
      hash = flz_hash(seq);
      ref = ip_start + htab[hash];
      htab[hash] = ip - ip_start;
      distance = ip - ref;
      cmp = FASTLZ_LIKELY(distance < MAX_FARDISTANCE) ? flz_readu32(ref) & 0xffffff : 0x1000000;
      if (FASTLZ_UNLIKELY(ip >= ip_limit)) break;
      ++ip;
    } while (seq != cmp);

    if (FASTLZ_UNLIKELY(ip >= ip_limit)) break;

    --ip;

    /* far, needs at least 5-byte match */
    if (distance >= MAX_L2_DISTANCE) {
      if (ref[3] != ip[3] || ref[4] != ip[4]) {
        ++ip;
        continue;
      }
    }

    if (FASTLZ_LIKELY(ip > anchor)) {
      op = flz_literals(ip - anchor, anchor, op);
    }

    uint32_t len = flz_cmp(ref + 3, ip + 3, ip_bound);
    op = flz2_match(len, distance, op);

    /* update the hash at match boundary */
    ip += len;
    seq = flz_readu32(ip);
    hash = flz_hash(seq & 0xffffff);
    htab[hash] = ip++ - ip_start;
    seq >>= 8;
    hash = flz_hash(seq);
    htab[hash] = ip++ - ip_start;

    anchor = ip;
  }

  uint32_t copy = (uint8_t*)input + length - anchor;
  op = flz_literals(copy, anchor, op);

  /* marker for fastlz2 */
  *(uint8_t*)output |= (1 << 5);

  return op - (uint8_t*)output;


// =========================================================================================
module std::compression::fastlz;

import std::math;


enum LzCompressionLevel : const int
{
	FASTEST = 1,
	BEST = 2,
}


faultdef
	INVALID_COMPRESSION_LEVEL, BUFFER_TOO_SMALL, OUT_OF_BOUNDS;


<*
Get the minimum desired output buffer size for a given input buffer size.

@require types::is_numerical($typeof(in_size)) : `Input buffer size must be numeric.`
*>
macro @size_wants(in_size) => (usz)math::ceil((float)in_size * 1.05);


<*
Compress a block of input data and store the result in the given output buffer.
Returns the size of the compressed input.

@param[in] input_data : `Input data to compress.`
@param[out] output_data : `Buffer to store compressed data. Must be at least the size of 'input_data'.`

@require input_data.len >= 16 : `Input buffer to compress must be at least 16 bytes.`
@require output_data.len >= math::ceil((float)input_data.len * 1.05) : `Output uffer must be at least 5% larger than the input buffer.`
@require output_data.ptr + output_data.len <= input_data.ptr || input_data.ptr + input_data.len <= output_data.ptr : `Buffer memory ranges cannot overlap.`

@ensure return <= output_data.len : `The compressed data size must be less than or equal to the size of the output buffer.`
*>
fn usz? compress(char[] input_data, char[] output_data, LzCompressionLevel level = FASTEST)
{
	switch (level)
	{
		case FASTEST:	return lz1_compress(input_data, output_data);
		case BEST:		return lz2_compress(input_data, output_data);

		default:		return INVALID_COMPRESSION_LEVEL?;
	}
}


<*
Decompress an input block of compressed data, into the output_data buffer. Return the length of the decompressed data.
Decompression is memory-safe and will never write beyond the output_data slice's length.

@param[in] input_data : `Input data to decompress.`
@param[out] output_data : `Buffer to store decompressed data. Must be at least the size of 'input_data'.`

@require input_data.len > 0 : `Input buffer to decompress must not be empty.`
@require output_data.ptr + output_data.len <= input_data.ptr || input_data.ptr + input_data.len <= output_data.ptr : `Buffer memory ranges cannot overlap.`

@ensure return <= output_data.len : `The compressed data size must be less than or equal to the size of the output buffer.`
*>
fn usz? decompress(char[] input_data, char[] output_data)
{
	LzCompressionLevel level = (LzCompressionLevel)((input_data[0] >> 5) + 1);

	switch (level)
	{
		case FASTEST:	return lz1_decompress(input_data, output_data);
		case BEST:		return lz2_decompress(input_data, output_data);

		default:		return INVALID_COMPRESSION_LEVEL?;
	}
}
