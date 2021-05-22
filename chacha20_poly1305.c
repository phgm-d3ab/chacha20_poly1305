#include "chacha20_poly1305.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

// figure out how many n byte blocks
// will fit in length x
#define align16(x) (x & ~15)
#define align64(x) (x & ~63)

// one u32 into 4x u8; (x: u32, y: u8 *)
#define u32_u8le(x, y)        \
    y[0] = x         & 0xff;  \
    y[1] = (x >> 8)  & 0xff;  \
    y[2] = (x >> 16) & 0xff;  \
    y[3] = (x >> 24) & 0xff   \

// 4x u8 into one u32
#define u8_u32le(x)         \
(                           \
    ((u32) x[0]        |    \
    ((u32) x[1] << 8)  |    \
    ((u32) x[2] << 16) |    \
    ((u32) x[3] << 24) )    \
)                           \

// rotate x left by n bits
#define rotl(x, n) ((x << n) | (x >> (-n & 31)))


///////////////////////////
///     chacha20        ///
///////////////////////////

// "expand 32-byte k"
#define CHACHA_CONSTANT1 0x61707865
#define CHACHA_CONSTANT2 0x3320646e
#define CHACHA_CONSTANT3 0x79622d32
#define CHACHA_CONSTANT4 0x6b206574

// chacha20 basic operation
#define QUARTERROUND(a, b, c, d)                            \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl(s[d], 16);      \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl(s[b], 12);      \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl(s[d], 8);       \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl(s[b], 7);       \


static inline void chacha20_block(const u32 input[16], u8 output[64])
{
    // state
    u32 s[16];

    for (u32 i = 0; i < 16; i++)
        s[i] = input[i];

    for (u8 i = 0; i < 10; i++)
    {
        QUARTERROUND(0, 4, 8, 12)
        QUARTERROUND(1, 5, 9, 13)
        QUARTERROUND(2, 6, 10, 14)
        QUARTERROUND(3, 7, 11, 15)

        QUARTERROUND(0, 5, 10, 15)
        QUARTERROUND(1, 6, 11, 12)
        QUARTERROUND(2, 7, 8, 13)
        QUARTERROUND(3, 4, 9, 14)
    }

    for (u8 i = 0; i < 16; i++)
        s[i] += input[i];

    for (u8 i = 0; i < 16; i++)
    {
        u32_u8le(s[i], (output + i * 4));
    }
}

static inline void chacha20_state(const u8 key[32], const u32 block_counter, const u8 nonce[12], u32 state[16])
{
    state[0] = CHACHA_CONSTANT1;
    state[1] = CHACHA_CONSTANT2;
    state[2] = CHACHA_CONSTANT3;
    state[3] = CHACHA_CONSTANT4;

    state[4] = u8_u32le(key);
    state[5] = u8_u32le((key + 4));
    state[6] = u8_u32le((key + 8));
    state[7] = u8_u32le((key + 12));
    state[8] = u8_u32le((key + 16));
    state[9] = u8_u32le((key + 20));
    state[10] = u8_u32le((key + 24));
    state[11] = u8_u32le((key + 28));

    state[12] = block_counter;

    state[13] = u8_u32le(nonce);
    state[14] = u8_u32le((nonce + 4));
    state[15] = u8_u32le((nonce + 8));

}

void chacha20_xor(const u8 key[32], const u8 nonce[12], const u32 counter, u8 *data, const u32 len)
{
    u8 keystream[64] = {0};
    u32 state[16];

    chacha20_state(key, counter, nonce, state);

    const u32 aligned = align64(len);
    const u32 remaining = len - aligned;

    for (u32 n = 0; n < aligned; n += 64)
    {
        chacha20_block(state, keystream);

        // counter
        state[12] += 1;

        for (u32 i = 0; i < 64; i++)
        {
            data[n + i] ^= keystream[i];
        }
    }

    if (remaining)
    {
        chacha20_block(state, keystream);

        for (u32 i = 0; i < remaining; i++)
        {
            data[aligned + i] ^= keystream[i];
        }
    }
}


///////////////////////////
///     poly1305        ///
///////////////////////////

static inline void poly_add(u32 a[5], const u32 b[5])
{
    u64 p[5] = {0};

    p[0] += (u64) a[0] + b[0];
    p[1] += (u64) a[1] + b[1];
    p[2] += (u64) a[2] + b[2];
    p[3] += (u64) a[3] + b[3];
    p[4] += (u64) a[4] + b[4];

    p[1] += (p[0] >> 32);
    p[2] += (p[1] >> 32);
    p[3] += (p[2] >> 32);
    p[4] += (p[3] >> 32);

    a[0] = (u32) p[0];
    a[1] = (u32) p[1];
    a[2] = (u32) p[2];
    a[3] = (u32) p[3];
    a[4] = (u32) p[4];
}

static inline void poly_mul(u32 a[5], const u32 b[4])
{
    u64 p[4] = {0};
    const u64 B[4] =
            {
                    5 * (b[0] >> 2), // !
                    5 * (b[1] >> 2),
                    5 * (b[2] >> 2),
                    5 * (b[3] >> 2),
            };

    /*
     *       a3     a2     a1     a0
     *  x    b3     b2     b1     b0
     *    --------------------------
     *    a3*b0  a2*b0  a1*b0  a0*b0
     *  + a2*b1  a1*b1  a0*b1
     *  + a1*b2  a0*b2
     *  + a0*b3
     *
     *  ...
     */
    p[0] = (u64) b[0] * a[0];
    p[1] = (u64) b[0] * a[1] + (u64) b[1] * a[0];
    p[2] = (u64) b[0] * a[2] + (u64) b[1] * a[1] + (u64) b[2] * a[0];
    p[3] = (u64) b[0] * a[3] + (u64) b[1] * a[2] + (u64) b[2] * a[1] + (u64) b[3] * a[0];

    /*
     *  ...
     *
     *  +                      a4*B0
     *  +               a4*B1  a3*B1
     *  +        a4*B2  a3*B2  a2*B2
     *  + a4*B3  a3*B3  a2*B3  a1*B3
     */
    p[0] += (B[0] * a[4] + B[1] * a[3] + B[2] * a[2] + B[3] * a[1]);
    p[1] += (B[1] * a[4] + B[2] * a[3] + B[3] * a[2]);
    p[2] += (B[2] * a[4] + B[3] * a[3]);
    p[3] += (B[3] * a[4]);

    // carry & recover bits
    const u64 bits = a[4] * (b[0] & 0b00000011) + (p[3] >> 32);
    u64 carry = 5 * (bits >> 2);

    carry += (u32) p[0];
    a[0] = (u32) carry;
    carry >>= 32;

    carry += (u32) p[1] + (p[0] >> 32);
    a[1] = (u32) carry;
    carry >>= 32;

    carry += (u32) p[2] + (p[1] >> 32);
    a[2] = (u32) carry;
    carry >>= 32;

    carry += (u32) p[3] + (p[2] >> 32);
    a[3] = (u32) carry;
    carry >>= 32;

    carry += (bits & 0b00000011);
    a[4] = (u32) carry;
}

/*
 *  poly1305 process full blocks
 */
static inline void poly_block(const u32 r[4],
                              const u8 input[16],
                              u32 accum[5])
{
    u32 block[5] = {0};

    block[0] = u8_u32le((input));
    block[1] = u8_u32le((input + 4));
    block[2] = u8_u32le((input + 8));
    block[3] = u8_u32le((input + 12));

    // add 2^128 to block
    block[4] = 1;

    poly_add(accum, block);
    poly_mul(accum, r);
}

/*
 *  zero pad and poly remaining bytes
 */
static inline void poly_tail(u32 accum[5],
                             const u32 r[4],
                             const u8 *buf,
                             const u32 remaining)
{
    // x5 u32
    u8 bytes[20] = {0};

    for (u32 i = 0; i < remaining; i++)
    {
        bytes[i] = buf[i];
    }

    // one bit beyond the number of octets
    bytes[remaining] = 1;

    poly_add(accum, (u32 *) bytes);
    poly_mul(accum, r);
}

/*
 *  complete poly & output tag
 */
static inline void poly_final(u32 accum[5], const u32 s[5], u8 *output)
{
    u64 final[4] = {0};

    u64 carry = (u64) 5 + accum[0];
    carry >>= 32;

    carry += accum[1];
    carry >>= 32;

    carry += accum[2];
    carry >>= 32;

    carry += accum[3];
    carry >>= 32;

    carry += accum[4];
    carry = 5 * (carry >> 2);

    poly_add(accum, s);

    // if carry > 0 here, this is equivalent to
    // subtracting 0x3fffffffffffffffffffffffffffffffb
    final[0] = carry + accum[0];
    final[1] = (final[0] >> 32) + accum[1];
    final[2] = (final[1] >> 32) + accum[2];
    final[3] = (final[2] >> 32) + accum[3];

    // return num_to_16_le_bytes(a)
    u32_u8le(((u32) final[0]), output);
    u32_u8le(((u32) final[1]), (output + 4));
    u32_u8le(((u32) final[2]), (output + 8));
    u32_u8le(((u32) final[3]), (output + 12));
}

static inline void poly1305_state(u32 r[4], u32 s[4], const u8 key[32])
{
    r[0] = u8_u32le((key));
    r[1] = u8_u32le((key + 4));
    r[2] = u8_u32le((key + 8));
    r[3] = u8_u32le((key + 12));

    // 'clamp' r
    r[0] &= 0x0fffffff;
    r[1] &= 0x0ffffffc;
    r[2] &= 0x0ffffffc;
    r[3] &= 0x0ffffffc;

    s[0] = u8_u32le((key + 16));
    s[1] = u8_u32le((key + 20));
    s[2] = u8_u32le((key + 24));
    s[3] = u8_u32le((key + 28));
}

/*
 *  main poly1305 operation
 *
 *  process a number of available blocks,
 *  process remaining bytes, output tag
 */
void poly1305_tag(const u8 key[32],
                  const u8 *buf,
                  const u32 len,
                  u8 out[16])
{
    u32 r[4] = {0};
    u32 s[5] = {0};
    u32 accum[5] = {0};

    poly1305_state(r, s, key);

    const u32 len_aligned = align16(len);
    const u32 remaining = len - len_aligned;

    for (u32 i = 0; i < len_aligned; i += 16)
    {
        poly_block(r, buf + i, accum);
    }

    if (remaining)
    {
        buf += len_aligned;
        poly_tail(accum, r, buf, remaining);
    }

    poly_final(accum, s, out);
}


///////////////////////////////////////
///     chacha20_poly1305 AEAD      ///
///////////////////////////////////////

/*
 *  initialize the states generating poly1305
 *  one time key as described in section 2.6
 */
static inline void aead_init(const u8 key[32],
                             const u8 nonce[12],
                             u32 chacha[16], u32 r[4], u32 s[4])
{
    chacha20_state(key, 0, nonce, chacha);

    u8 block[64];
    chacha20_block(chacha, block);

    // use this block for poly otk
    poly1305_state(r, s, block);

    // counter
    chacha[12] = 1;
}

static inline void aead_poly_padded(const u8 *data,
                                    const u32 len,
                                    u32 accum[5],
                                    u32 r[4])
{
    const u32 aligned = align16(len);
    const u32 remaining = len - aligned;

    for (u32 i = 0; i < aligned; i += 16)
    {
        poly_block(r, (data + i), accum);
    }

    // pad and process one last block
    if (remaining)
    {
        // zeroes are important
        u8 block[16] = {0};
        data += aligned;

        for (u32 i = 0; i < remaining; i++)
        {
            block[i] = data[i];
        }

        poly_block(r, block, accum);
    }
}

/*
 *  final parts of authentication tag input:
 *  The length of the additional data in octets (as a 64-bit little-endian integer).
 *  The length of the ciphertext in octets (as a 64-bit little-endian integer).
 *
 *  but since we are using u32, some of
 *  these bytes will always remain zeroes
 */
static inline void aead_poly_final(const u32 aad_len, const u32 data_len, const u32 r[4], u32 accum[5])
{
    const u8 block[16] =
            {
                    (u8) (aad_len),
                    (u8) (aad_len >> 8),
                    (u8) (aad_len >> 16),
                    (u8) (aad_len >> 24),
                    0, 0, 0, 0,

                    (u8) (data_len),
                    (u8) (data_len >> 8),
                    (u8) (data_len >> 16),
                    (u8) (data_len >> 24),
                    0, 0, 0, 0
            };

    poly_block(r, block, accum);
}

void chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                               const u8 *aad, uint32_t aad_len,
                               const u8 *data, uint32_t data_len,
                               u8 *ciphertext, uint8_t tag[16])
{
    u32 chacha[16] = {0};
    u8 keystream[64] = {0};

    u32 accum[5] = {0};
    u32 r[4] = {0};
    u32 s[5] = {0};

    aead_init(key, nonce, chacha, r, s);
    aead_poly_padded(aad, aad_len, accum, r);

    const u32 len_aligned = align64(data_len);
    const u32 remaining = data_len - len_aligned;

    // [        chacha        ]
    // [poly][poly][poly][poly]
    for (u32 n = 0; n < len_aligned; n += 64)
    {
        chacha20_block(chacha, keystream);
        chacha[12] += 1;

        for (u32 i = 0; i < 64; i++)
        {
            ciphertext[n + i] = (data[n + i] ^ keystream[i]);
        }

        poly_block(r, (ciphertext + n), accum);
        poly_block(r, (ciphertext + n + 16), accum);
        poly_block(r, (ciphertext + n + 32), accum);
        poly_block(r, (ciphertext + n + 48), accum);
    }

    // one last chacha keystream + poly blocks
    if (remaining)
    {
        data += len_aligned;
        ciphertext += len_aligned;

        chacha20_block(chacha, keystream);
        for (u32 n = 0; n < remaining; n++)
        {
            ciphertext[n] = (data[n] ^ keystream[n]);
        }

        aead_poly_padded(ciphertext, remaining, accum, r);
    }

    aead_poly_final(aad_len, data_len, r, accum);
    poly_final(accum, s, tag);
}

u32 chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, uint32_t aad_len,
                              const uint8_t *ciphertext, uint32_t cipher_len,
                              const uint8_t tag[12], uint8_t *output)
{
    u32 chacha[16] = {0};
    u8 keystream[64] = {0};

    u32 accum[5] = {0};
    u32 r[4] = {0};
    u32 s[5] = {0};

    aead_init(key, nonce, chacha, r, s);
    aead_poly_padded(aad, aad_len, accum, r);

    const u32 len_aligned = align64(cipher_len);
    const u32 remaining = cipher_len - len_aligned;

    // [poly][poly][poly][poly]
    // [        chacha        ]
    for (u32 n = 0; n < len_aligned; n += 64)
    {
        poly_block(r, (ciphertext + n), accum);
        poly_block(r, (ciphertext + n + 16), accum);
        poly_block(r, (ciphertext + n + 32), accum);
        poly_block(r, (ciphertext + n + 48), accum);

        chacha20_block(chacha, keystream);
        chacha[12] += 1;

        for (u32 i = 0; i < 64; i++)
        {
            output[n + i] = (ciphertext[n + i] ^ keystream[i]);
        }
    }

    // last poly blocks + one chacha
    if (remaining)
    {
        ciphertext += len_aligned;
        output += len_aligned;

        aead_poly_padded(ciphertext, remaining, accum, r);
        chacha20_block(chacha, keystream);

        for (u32 n = 0; n < remaining; n++)
        {
            output[n] = (ciphertext[n] ^ keystream[n]);
        }
    }

    aead_poly_final(aad_len, cipher_len, r, accum);

    // finally, compare tags
    u8 tag_local[16] = {0};
    u32 diff = 0;

    poly_final(accum, s, tag_local);

    for (u32 i = 0; i < 16; i++)
    {
        diff |= (tag_local[i] ^ tag[i]);
    }

    return diff;
}
