#include <stdint.h>
#include <crypto_lib_types.h>
#include <crypto_common.h>
#include <crypto_hash_intf.h>

static struct crypto_lib_type_msg {
    crypto_lib_type_t type;
    const char *str;
} crypto_lib_types_str[] = {
    {CRYPTO_LIB_OPENSSL, "OpenSSL"},
    {CRYPTO_LIB_WOLFSSL, "WolfSSL"},
    {CRYPTO_LIB_MBEDTLS, "MbedTLS"},
};

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

const char *crypto_get_lib_type_str(crypto_lib_type_t type)
{
    return crypto_lib_types_str[type].str;
}

