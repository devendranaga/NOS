#include <mbedtls/cipher.h>
#include <mbedtls_crypto_random.h>
#include <mbedtls_aes_cbc.h>
#include <nos_core.h>
#include <mbedtls_crypto_random.h>

namespace nos::crypto
{

mbedtls_aes_cbc::mbedtls_aes_cbc() { }
mbedtls_aes_cbc::~mbedtls_aes_cbc() { }

static int encrypt(const mbedtls_cipher_info_t *cipher_info,
                   const crypto_symmetric_key &key_in,
                   const uint8_t *msg_in,
                   uint32_t msg_len_in,
                   crypto_iv &iv_out,
                   uint8_t *msg_out)
{
    mbedtls_cipher_context_t ctx;
    mbedtls_random r;
    size_t enc_len = 0;
    int ret = -1;

    ret = r.get(iv_out.iv, sizeof(iv_out.iv));
    if (ret != 0) {
        return -1;
    }
    iv_out.iv_len = sizeof(iv_out.iv);

    mbedtls_cipher_init(&ctx);
    ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        ret = -1;
        goto err;
    }
    mbedtls_cipher_setkey(&ctx, key_in.key,
                          key_in.key_len * 8, MBEDTLS_ENCRYPT);
    ret = mbedtls_cipher_crypt(&ctx, iv_out.iv,
                               iv_out.iv_len, msg_in,msg_len_in,
                               msg_out, &enc_len);
    if (ret != 0) {
        ret = -1;
        goto err;
    }

    ret = enc_len;
err:
    mbedtls_cipher_free(&ctx);
    return ret;
}

int mbedtls_aes_cbc::encrypt_128(const crypto_symmetric_key &key_in,
                             const uint8_t *msg_in,
                             uint32_t msg_len_in,
                             crypto_iv &iv_out,
                             uint8_t *msg_out)
{
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_type(
                    MBEDTLS_CIPHER_AES_128_CBC);
    return encrypt(cipher_info, key_in, msg_in,
                   msg_len_in, iv_out, msg_out);
}

int mbedtls_aes_cbc::encrypt_192(const crypto_symmetric_key &key_in,
                                 const uint8_t *msg_in,
                                 uint32_t msg_len_in,
                                 crypto_iv &iv_out,
                                 uint8_t *msg_out)
{
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_type(
                    MBEDTLS_CIPHER_AES_192_CBC);
    return encrypt(cipher_info, key_in, msg_in,
                   msg_len_in, iv_out, msg_out);
}

int mbedtls_aes_cbc::encrypt_256(const crypto_symmetric_key &key_in,
                                 const uint8_t *msg_in,
                                 uint32_t msg_len_in,
                                 crypto_iv &iv_out,
                                 uint8_t *msg_out)
{
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_type(
                    MBEDTLS_CIPHER_AES_256_CBC);
    return encrypt(cipher_info, key_in, msg_in,
                   msg_len_in, iv_out, msg_out);
}

static int decrypt(const mbedtls_cipher_info_t *cipher_info,
                   const crypto_symmetric_key &key_in,
                   const uint8_t *enc_in,
                   uint32_t enc_len_in,
                   const crypto_iv &iv_in,
                   uint8_t *msg_out)
{
    mbedtls_cipher_context_t ctx;
    size_t dec_len = 0;
    int ret = -1;

    mbedtls_cipher_init(&ctx);
    ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        ret = -1;
        goto err;
    }
    mbedtls_cipher_setkey(&ctx, key_in.key,
                          key_in.key_len * 8, MBEDTLS_DECRYPT);
    ret = mbedtls_cipher_crypt(&ctx, iv_in.iv, iv_in.iv_len,
                               enc_in, enc_len_in,
                               msg_out, &dec_len);
    if (ret != 0) {
        ret = -1;
        goto err;
    }

    ret = dec_len;

err:
    mbedtls_cipher_free(&ctx);
    return ret;
}

int mbedtls_aes_cbc::decrypt_128(const crypto_symmetric_key &key_in,
                                 const uint8_t *enc_in,
                                 uint32_t enc_len_in,
                                 const crypto_iv &iv_in,
                                 uint8_t *msg_out)
{
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_type(
                    MBEDTLS_CIPHER_AES_128_CBC);
    return decrypt(cipher_info, key_in, enc_in,
                   enc_len_in, iv_in, msg_out);
}

int mbedtls_aes_cbc::decrypt_192(const crypto_symmetric_key &key_in,
                                 const uint8_t *enc_in,
                                 uint32_t enc_len_in,
                                 const crypto_iv &iv_in,
                                 uint8_t *msg_out)
{
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_type(
                    MBEDTLS_CIPHER_AES_192_CBC);
    return decrypt(cipher_info, key_in, enc_in,
                   enc_len_in, iv_in, msg_out);
}

int mbedtls_aes_cbc::decrypt_256(const crypto_symmetric_key &key_in,
                                 const uint8_t *enc_in,
                                 uint32_t enc_len_in,
                                 const crypto_iv &iv_in,
                                 uint8_t *msg_out)
{
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_type(
                    MBEDTLS_CIPHER_AES_256_CBC);
    return decrypt(cipher_info, key_in, enc_in,
                   enc_len_in, iv_in, msg_out);
}

}
