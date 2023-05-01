#ifndef __AOS_CRYPTO_COMMON_H__
#define __AOS_CRYPTO_COMMON_H__

#include <stdint.h>

int crypto_safe_memcmp(const uint8_t *src,
                       const uint8_t *dst, uint32_t len);
const char *crypto_get_lib_type_str(crypto_lib_type_t type);

#endif
