#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <crypto_impl.h>
#include <crypto_buffers.h>
#include <nos_crypto_hash_intf.h>
#include <nos_crypto_hmac_intf.h>
#include <openssl_hmac.h>

namespace nos::crypto
{

static const struct hmac_map {
    hash_function_types type;
    const char *hmac;
} hmac_list[] = {
    {hash_function_types::SHA2_256, "SHA256"},
    {hash_function_types::SHA2_384, "SHA384"},
    {hash_function_types::SHA2_512, "SHA512"},
    {hash_function_types::SHA3_256, "SHA3-256"},
    {hash_function_types::SHA3_384, "SHA3-384"},
    {hash_function_types::SHA3_512, "SHA3-512"},
};

const char *get_hmac_str(const hash_function_types type)
{
    for (uint32_t i = 0; i < sizeof(hmac_list) / sizeof(hmac_list[0]); i ++) {
        if (hmac_list[i].type == type) {
            return hmac_list[i].hmac;
        }
    }

    return nullptr;
}

int openssl_hmac_intf::generate(hash_function_types hash_type,
                                crypto_symmetric_key &key_in,
                                uint8_t *msg_in, uint32_t msg_len,
                                crypto_mac_buffer &mac_out)
{
    const EVP_MD *md;
    const char *hmac_str;
    int ret;

    hmac_str = get_hmac_str(hash_type);
    if (!hmac_str) {
        return -1;
    }

    md = EVP_get_digestbyname(hmac_str);
    if (md == NULL) {
        return -1;
    }

    if (HMAC(md,
             key_in.key, key_in.key_len, msg_in,
             msg_len, mac_out.signature, &mac_out.signature_len)) {
        return 0;
    }

    return -1;
}

int openssl_hmac_intf::verify(hash_function_types hash_type,
                              crypto_symmetric_key &key_in,
                              uint8_t *msg_in, uint32_t msg_len,
                              crypto_mac_buffer &mac_out)
{
    const EVP_MD *md;
    const char *hmac_str;
    int ret;

    hmac_str = get_hmac_str(hash_type);
    if (!hmac_str) {
        return -1;
    }

    md = EVP_get_digestbyname(hmac_str);
    if (md == NULL) {
        return -1;
    }

    if (HMAC(md,
             key_in.key, key_in.key_len, msg_in,
             msg_len, mac_out.signature, &mac_out.signature_len)) {
        return 0;
    }

    return -1;
}

}
