#include <stdint.h>
#include <stdbool.h>
#include <crypto_mac_intf.h>
#include <crypto_common.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static int openssl_hmac_generate(const EVP_MD *md,
                                 const uint8_t *key,
                                 uint32_t key_size,
                                 const uint8_t *buf_in, uint32_t buf_size,
                                 uint8_t *buf_out)
{
    uint32_t signature = 0;

    HMAC(md, key, key_size, buf_in, buf_size, buf_out, &signature);

    return signature;
}

int openssl_mac_generate(crypto_mac_params_in_t *mac_data_in,
                         crypto_mac_params_out_t *mac_data_out)
{
    uint8_t key[64] = {0};
    int keylen = 0;

    OpenSSL_add_all_algorithms();

    keylen = crypto_get_key(mac_data_in->keyfile, key);

    switch (mac_data_in->mac_type) {
        case CRYPTO_MAC_TYPE_HMAC_SHA2_256:
            mac_data_out->data_len = openssl_hmac_generate(EVP_sha256(),
                                                           key, keylen,
                                                           mac_data_in->buf_in,
                                                           mac_data_in->buf_size,
                                                           mac_data_out->data);
        break;
        default:
            return -1;
    }

    return 0;
}

bool openssl_mac_verify(crypto_mac_params_in_t *mac_data_in,
                       crypto_mac_params_out_t *mac_data_out)
{
    return -1;
}

