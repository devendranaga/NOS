#include <stdint.h>

int crypto_safe_memcmp(const uint8_t *src,
                       const uint8_t *dst, uint32_t len)
{
    uint32_t i;
    uint32_t fail = 0;

    for (i = 0; i < len; i ++) {
        if (src[i] != dst[i]) {
            fail = -1;
        }
    }

    return fail;
}
