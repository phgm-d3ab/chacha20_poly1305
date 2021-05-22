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


// generate 128 bit tag using 256 bit key
void poly1305_tag(const uint8_t key[32],
                  const uint8_t *data,
                  uint32_t len,
                  uint8_t tag[16]);

// encrypt/decrypt (xor keystream bytes) some data in-place
// using 256 bit key, 96 bit nonce and block counter
void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                  uint32_t counter, uint8_t *data, uint32_t len);


// encrypt some data and calculate authentication tag
// data_len bytes of ciphertext is placed into output
void chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, uint32_t aad_len,
                               const uint8_t *data, uint32_t data_len,
                               uint8_t *output, uint8_t tag[16]);

// authenticate and decrypt some data
// returns non-zero value to indicate failure
uint32_t chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                   const uint8_t *aad, uint32_t aad_len,
                                   const uint8_t *ciphertext, uint32_t cipher_len,
                                   const uint8_t tag[12], uint8_t *output);


#ifdef __cplusplus
}
#endif
#endif // CHACHA20_POLY1305_H
