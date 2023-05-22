#ifndef __AOS_CRYPTO_COMMON_H__
#define __AOS_CRYPTO_COMMON_H__

#include <stdint.h>

/**
 * @brief - Safely compare two buffers.
 * 
 * @param[in] src - src buffer.
 * @param[in] dst - dst buffer.
 * @param[in] len - buffer length.
 * 
 * @return 0 on success -1 on failure.
*/
int crypto_safe_memcmp(const uint8_t *src,
                       const uint8_t *dst, uint32_t len);
const char *crypto_get_lib_type_str(crypto_lib_type_t type);

int crypto_get_key(const char *key_file, uint8_t *key);

#endif
