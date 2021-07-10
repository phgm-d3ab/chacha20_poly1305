/*
 *  test poly & chacha against RFC vectors
 */
#include <stdint.h>

#include "chacha20_poly1305.h"

// section A.2
int chacha20_test();

// section A.3
int poly1305_test();

// 2.8.2 + A.5
int aead_test();
