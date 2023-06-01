#include <mbedtls/nist_kw.h>
#include <mbedtls/aes.h>
#include <mbedtls_keywraps.h>

namespace nos::crypto {

int mbedtls_keywrap::wrap(const std::string &kek,
                         const std::string &tbw_key,
                         const std::string &wrapped_key)
{
    return -1;
}

int mbedtls_keywrap::unwrap(const std::string &kek,
                           const std::string &wrapped_key,
                           const std::string &unwrapped_key)
{
    return -1;
}

int mbedtls_keywrap::wrap(const crypto_symmetric_key &kek,
                          crypto_symmetric_key &tbw_key,
                          crypto_symmetric_key &wrapped_key)
{
    mbedtls_nist_kw_context kw;
    int ret;

    mbedtls_nist_kw_init(&kw);
    ret = mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES,
                                 kek.key, kek.key_len * 8, 1);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_nist_kw_wrap(&kw, MBEDTLS_KW_MODE_KW,
                               tbw_key.key, tbw_key.key_len,
                               wrapped_key.key,
                               (size_t *)&wrapped_key.key_len,
                               sizeof(wrapped_key.key));
    if (ret != 0) {
        return -1;
    }

    mbedtls_nist_kw_free(&kw);

    return 0;
}

int mbedtls_keywrap::unwrap(const crypto_symmetric_key &kek,
                            crypto_symmetric_key &wrapped_key,
                            crypto_symmetric_key &unwrapped_key)
{
    mbedtls_nist_kw_context kw;
    int ret;

    mbedtls_nist_kw_init(&kw);
    ret = mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES,
                                 kek.key, kek.key_len * 8, 0);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_nist_kw_wrap(&kw, MBEDTLS_KW_MODE_KW,
                               wrapped_key.key, wrapped_key.key_len,
                               unwrapped_key.key,
                               (size_t *)&unwrapped_key.key_len,
                               sizeof(unwrapped_key.key));
    if (ret != 0) {
        return -1;
    }

    mbedtls_nist_kw_free(&kw);

    return 0;
}

}
