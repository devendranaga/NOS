#include <stdio.h>
#include <crypto_intf.h>
#include <mbedtls_crypto_intf.h>

static crypto_hash_intf_t mbedtls_crypto_hash_if = {
    .hash  = mbedtls_hash,
};

static crypto_intf_t mbedtls_crypto_if = {
    .hash_intf = &mbedtls_crypto_hash_if,
    .mac_intf  = NULL,
};

int mbedtls_crypto_intf_init()
{
    int ret;

    ret = register_crypto_intf(CRYPTO_LIB_MBEDTLS, &mbedtls_crypto_if);
    if (ret < 0) {
        return -1;
    }

    return 0;
}
