/*
 *  test poly & chacha against RFC vectors
 */
#include <stdint.h>

#include "chacha20_poly1305.h"

// section A.2
void chacha20_test();

// section A.3
void poly1305_test();

// 2.8.2 + A.5
void aead_test();
