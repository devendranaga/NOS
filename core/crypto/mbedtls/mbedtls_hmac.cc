#include <crypto_impl.h>
#include <crypto_buffers.h>
#include <nos_crypto_hash_intf.h>
#include <nos_crypto_hmac_intf.h>
#include <mbedtls_hmac.h>
#include <mbedtls/md.h>

namespace nos::crypto {

int mbedtls_hmac_intf::generate(hash_function_types hash_type,
                                crypto_symmetric_key &key_in,
                                uint8_t *msg_in, uint32_t msg_len,
                                crypto_mac_buffer &mac_out)
{
    const mbedtls_md_info_t *md;
    mbedtls_md_context_t ctx;
    int ret;

    switch (hash_type) {
        case hash_function_types::SHA2_256:
            md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            mac_out.signature_len = 32;
        break;
        case hash_function_types::SHA2_384:
            md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            mac_out.signature_len = 48;
        break;
        case hash_function_types::SHA2_512:
            md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            mac_out.signature_len = 64;
        break;
        default:
            return -1;
    }

    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_md_hmac_starts(&ctx, key_in.key, key_in.key_len);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_md_hmac_update(&ctx, msg_in, msg_len);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_md_hmac_finish(&ctx, mac_out.signature);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

int mbedtls_hmac_intf::verify(hash_function_types hash_type,
                              crypto_symmetric_key &key_in,
                              uint8_t *msg_in, uint32_t msg_len,
                              crypto_mac_buffer &mac_out)
{
    const mbedtls_md_info_t *md;
    mbedtls_md_context_t ctx;
    uint8_t signature[64];
    int ret;

    switch (hash_type) {
        case hash_function_types::SHA2_256:
            md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            mac_out.signature_len = 32;
        break;
        case hash_function_types::SHA2_384:
            md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            mac_out.signature_len = 48;
        break;
        case hash_function_types::SHA2_512:
            md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            mac_out.signature_len = 64;
        break;
        default:
            return -1;
    }

    ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_md_hmac_starts(&ctx, key_in.key, key_in.key_len);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_md_hmac_update(&ctx, msg_in, msg_len);
    if (ret != 0) {
        return -1;
    }

    ret = mbedtls_md_hmac_finish(&ctx, signature);
    if (ret != 0) {
        return -1;
    }

    ret = memcmp(mac_out.signature, signature, mac_out.signature_len);

    return (ret == 0) ? 0 : -1;
}

}
