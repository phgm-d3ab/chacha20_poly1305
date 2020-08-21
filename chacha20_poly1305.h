/*
 *  C implementation of Daniel J. Bernstein's
 *  Poly1305 & Chacha20, RFC8439 (7539).
 */
#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#ifdef __cplusplus
extern "C" {
#include <cstdint>
#else
#include <stdint.h>
#endif


/// * Poly1305 * ///

// generate 128 bit tag using key
void poly1305_tag(const uint8_t *key,
                  const uint8_t *data,
                  uint32_t len,
                  uint8_t tag[16]);


/// * ChaCha20 * ///

typedef struct
{
    uint32_t state[12];

} chacha20_ctx;

// initialize an instance of chacha20_ctx with 256 bit key
void chacha20_init(chacha20_ctx *, const uint8_t *key);

// set 96 bit nonce and counter
void chacha20_nonce(chacha20_ctx *, const uint8_t *nonce, uint32_t counter);

// use chacha20_ctx to encrypt data
void chacha20_encrypt(const chacha20_ctx *, uint8_t *data, uint32_t len);

// use chacha20_ctx to decrypt data
void chacha20_decrypt(const chacha20_ctx *, uint8_t *data, uint32_t len);


/// * AEAD * ///

typedef struct
{
    uint32_t constant;
    uint64_t nonce;

    uint8_t *aad;
    uint32_t aad_len;

    uint8_t *data;
    uint32_t data_len;

    uint8_t *tag;

} aead_args;

// encrypt data and compute authenticator
void aead_encrypt(const uint8_t *key, const aead_args *);

// authenticate and decrypt data
// returns non-zero to indicate failure
uint32_t aead_decrypt(const uint8_t *key, const aead_args *);


#ifdef __cplusplus
}
#endif

#endif // CHACHA20_POLY1305_H
