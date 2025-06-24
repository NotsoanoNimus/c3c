/**
 * BLAKE hashing implementations for C3.
 *
 *   Based on the reference C implementation for BLAKE, which was part of the SHA-3 finalists.
 */
module std::hash::blake;


struct Blake256
{
    uint[8] hash_state;
    uint[4] sub_state;
    uint[2] t;
    int null_t;
    int buffer_length;
    char[64] buffer;
}
const uint[8] BLAKE256_INIT @local = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

typedef Blake224 = Blake256;
const uint[8] BLAKE224_INIT @local = {};

struct Blake512
{
    ulong[8] hash_state;
    uint[4] sub_state;
    uint[2] t;
    int null_t;
    int buffer_length;
    char[128] buffer;
}
const ulong[8] BLAKE512_INIT @local = {};

typedef Blake384 = Blake512;
const ulong[8] BLAKE384_INIT @local = {};


faultdef INVALID_HASH_SIZE;


const char[16][16] SIGMA @local = {
    {  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3  },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4  },
    {  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    {  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    {  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11  },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10  },
    {  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13 , 0 },
    {  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3  },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4  },
    {  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    {  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    {  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }
};

const uint[16] U256 @local = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

const ulong[16] U512 @local = {
    0x243f6a8885a308d3, 0x13198a2e03707344,
    0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c,
    0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
    0x9216d5d98979fb1b, 0xd1310ba698dfb5ac,
    0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
    0xba7c9045f12c7f99, 0x24a19947b3916cf7,
    0x0801f2e2858efc16, 0x636920d871574e69
};

const char[129] PADDING @local = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


<*
    @require $width == 64 ||| $width == 32
*>
macro @rot($width, x, n) @local => ((x) << ($width - (n))) | ((x) >> (n));

macro @g($table, v, m, i, a, b, c, d, e) @local
{
    v[a] += (m[SIGMA[i][e]] ^ $table[SIGMA[i][e+1]]) + v[b];
    v[d]  = @rot(32, v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b]  = @rot(32, v[b] ^ v[c], 12);
    v[a] += (m[SIGMA[i][e+1]] ^ $table[SIGMA[i][e]])+v[b];
    v[d]  = @rot(32, v[d] ^ v[a], 8);
    v[c] += v[d];
    v[b]  = @rot(32, v[b] ^ v[c], 7);
}

// TODO: STD likely has these methods already and we can import them.
macro @u8_32_be(p) @local => ((uint)((p)[0]) << 24) | ((uint)((p)[1]) << 16) | ((uint)((p)[2]) <<  8) | ((uint)((p)[3]));

macro @u8_64_be(p, v) @local => ((ulong)@u8_32_be(p) << 32) | (ulong)@u8_32_be((p) + 4);

macro @u32_8_be(p, v) @local
{
    (p)[0] = (char)((v) >> 24);
    (p)[1] = (char)((v) >> 16);
    (p)[2] = (char)((v) >>  8);
    (p)[3] = (char)((v) >>  0);
}

macro @u64_8_be(p, v) @local
{
    @u32_8_be((p) + 0, (uint)((v) >> 32));
    @u32_8_be((p) + 4, (uint)((v) >>  0));
}


fn void Blake256.init(&self) => *self = { .hash_state = BLAKE256_INIT };

<*
    @param [in] input
    @require input.len <= uint.max
*>
fn void Blake256.update(&self, char[] input)
{
    int left = self.buffer_length;
    int fill = 64 - left;
    ulong inlen = input.len;
    char* in = input.ptr;

    if (left && inlen >= fill)
    {
        for (int i = 0; i < fill; ++i) self.buffer[left + i] = in[i];
        self.t[0] += 512;
        if (!self.t[0]) self.t[1]++;

        {
            uint[16] v;
            uint[16] m;
            uint i;
            char[] block = &self.buffer;

            for (i = 0; i < 16; ++i) m[i] = @u8_32_be(&block[0 + i * 4]);

            for (i = 0; i < 8; ++i) v[i] = self.hash_state[i];

            v[ 8] = self.sub_state[0] ^ U256[0];
            v[ 9] = self.sub_state[1] ^ U256[1];
            v[10] = self.sub_state[2] ^ U256[2];
            v[11] = self.sub_state[3] ^ U256[3];
            v[12] = U256[4];
            v[13] = U256[5];
            v[14] = U256[6];
            v[15] = U256[7];

            if (!self.null_t)
            {
                v[12] ^= self.t[0];
                v[13] ^= self.t[0];
                v[14] ^= self.t[1];
                v[15] ^= self.t[1];
            }

            for (i = 0; i < 14; ++i)
            {
                @g(U256, v, m, i,   0,  4,  8, 12,  0);
                @g(U256, v, m, i,   1,  5,  9, 13,  2);
                @g(U256, v, m, i,   2,  6, 10, 14,  4);
                @g(U256, v, m, i,   3,  7, 11, 15,  6);
                @g(U256, v, m, i,   0,  5, 10, 15,  8);
                @g(U256, v, m, i,   1,  6, 11, 12, 10);
                @g(U256, v, m, i,   2,  7,  8, 13, 12);
                @g(U256, v, m, i,   3,  4,  9, 14, 14);
            }

            for (i = 0; i < 16; ++i) self.hash_state[i % 8] ^= v[i];

            for (i = 0; i < 8 ; ++i) self.hash_state[i] ^= self.sub_state[i % 4];
        }

        in += fill;
        inlen -= fill;
        left = 0;
    }

    while (inlen >= 64)
    {
        self.t[0] += 512;
        if (!self.t[0]) self.t[1]++;

                {
            uint[16] v;
            uint[16] m;
            uint i;
            char[] block = in[:64];

            for (i = 0; i < 16; ++i) m[i] = @u8_32_be(&block[0 + i * 4]);

            for (i = 0; i < 8; ++i) v[i] = self.hash_state[i];

            v[ 8] = self.sub_state[0] ^ U256[0];
            v[ 9] = self.sub_state[1] ^ U256[1];
            v[10] = self.sub_state[2] ^ U256[2];
            v[11] = self.sub_state[3] ^ U256[3];
            v[12] = U256[4];
            v[13] = U256[5];
            v[14] = U256[6];
            v[15] = U256[7];

            if (!self.null_t)
            {
                v[12] ^= self.t[0];
                v[13] ^= self.t[0];
                v[14] ^= self.t[1];
                v[15] ^= self.t[1];
            }

            for (i = 0; i < 14; ++i)
            {
                @g(U256, v, m, i,   0,  4,  8, 12,  0);
                @g(U256, v, m, i,   1,  5,  9, 13,  2);
                @g(U256, v, m, i,   2,  6, 10, 14,  4);
                @g(U256, v, m, i,   3,  7, 11, 15,  6);
                @g(U256, v, m, i,   0,  5, 10, 15,  8);
                @g(U256, v, m, i,   1,  6, 11, 12, 10);
                @g(U256, v, m, i,   2,  7,  8, 13, 12);
                @g(U256, v, m, i,   3,  4,  9, 14, 14);
            }

            for (i = 0; i < 16; ++i) self.hash_state[i % 8] ^= v[i];

            for (i = 0; i < 8 ; ++i) self.hash_state[i] ^= self.sub_state[i % 4];
        }

        in += 64;
        inlen -= 64;
    }

    if (inlen)
    {
        for (int i = 0; i < inlen; ++i) self.buffer[left + i] = in[i];
        self.buffer_length = left + (int)inlen;
    }
    else
    {
        self.buffer_length = 0;
    }
}

fn char[32] Blake256.final(&self)
{
    char[32] result;
    char[8] msglen;
    char zo = 0x01;
    char oo = 0x81;

    uint lo = self.t[0] + (self.buffer_length << 3);
    uint hi = self.t[1];

    if (lo < (self.buffer_length << 3)) hi++;

    @u32_8_be(&msglen[0], hi);
    @u32_8_be(&msglen[4], lo);

    if (self.buffer_length == 55)
    {
        self.t[0] -= 8;
        self.update(PADDING[:(55 - self.buffer_length)]);
    }
    else
    {
        if (self.buffer_length < 55)
        {
            if (!self.buffer_length) self.null_t = 1;

            self.t[0] -= 440 - (self.buffer_length << 3);
            self.update(PADDING[:(55 - self.buffer_length)]);
        }
        else
        {
            self.t[0] -= 512 - (self.buffer_length << 3);
            self.update(PADDING[:(64 - self.buffer_length)]);
            self.t[0] -= 440;
            self.update(PADDING[1:55]);
            self.null_t = 1;
        }

        self.update(((char[*]*)&zo)[:1]);
        self.t[0] -= 8;
    }

    self.t[0] -= 64;
    self.update(msglen[:8]);

    @u32_8_be(&result[0],  self.hash_state[0]);
    @u32_8_be(&result[4],  self.hash_state[1]);
    @u32_8_be(&result[8],  self.hash_state[2]);
    @u32_8_be(&result[12], self.hash_state[3]);
    @u32_8_be(&result[16], self.hash_state[4]);
    @u32_8_be(&result[20], self.hash_state[5]);
    @u32_8_be(&result[24], self.hash_state[6]);
    @u32_8_be(&result[28], self.hash_state[7]);

    return result;
}


fn void Blake224.init(&self) => *self = { .hash_state = BLAKE224_INIT };


fn void Blake512.init(&self) => *self = { .hash_state = BLAKE512_INIT };


fn void Blake384.init(&self) => *self = { .hash_state = BLAKE384_INIT };


<*
    @require $length == 224 ||| $length == 256 ||| $length == 384 ||| $length == 512
*>
macro char[*] @hash($length, char[] input) @local
{
    $switch $length:
        $case 224:
            Blake224 s @noinit;
        $case 256:
            Blake256 s @noinit;
        $case 384:
            Blake384 s @noinit;
        $case 512:
            Blake512 s @noinit;
    $endswitch

    s.init();
    s.update(input);

    return s.final();
}

macro blake224(char[] input) => @hash(224, input);
macro blake256(char[] input) => @hash(256, input);
macro blake384(char[] input) => @hash(384, input);
macro blake512(char[] input) => @hash(512, input);

