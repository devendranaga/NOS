#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>

int test_keywrap();

int test_hmac(nos::crypto::crypto_impl impl);

int test_hkdf();

int test_hash();

int test_aes_cmac();

int test_aes_cbc(nos::crypto::crypto_impl impl);

int main()
{
    nos::crypto::crypto_impl impl[] = {
        nos::crypto::crypto_impl::mbedtls,
        nos::crypto::crypto_impl::openssl,
    };
    int ret;

    ret = test_hash();
    if (ret != 0) {
        return -1;
    }

    ret = test_keywrap();
    if (ret != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < sizeof(impl) / sizeof(impl[0]); i ++) {
        ret = test_hmac(impl[i]);
        if (ret != 0) {
            return -1;
        }
    }

    ret = test_hkdf();
    if (ret != 0) {
        return -1;
    }

    ret = test_aes_cmac();
    if (ret != 0) {
        return -1;
    }

    ret = test_aes_cbc(nos::crypto::crypto_impl::mbedtls);
    if (ret != 0) {
        return -1;
    }

    return 0;
}
