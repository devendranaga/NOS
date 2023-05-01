#include <stdio.h>
#include <crypto_intf.h>
#include <openssl_crypto_intf.h>

static crypto_hash_intf_t openssl_crypto_hash_if = {
    .hash  = openssl_hash,
};

static crypto_intf_t openssl_crypto_if = {
    .hash_intf = &openssl_crypto_hash_if,
    .mac_intf  = NULL,
};

int openssl_crypto_intf_init()
{
    int ret;

    ret = register_crypto_intf(CRYPTO_LIB_OPENSSL, &openssl_crypto_if);
    if (ret < 0) {
        return -1;
    }

    return 0;
}
