#include "chacha20_poly1305_test.h"

#include <stdlib.h>

int main()
{
    if (poly1305_test() || chacha20_test() || aead_test())
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
