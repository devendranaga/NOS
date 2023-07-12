#include <openssl/evp.h>
#include <openssl_random.h>
#include <openssl_aes_cbc.h>
#include <nos_core.h>

namespace nos::crypto
{

openssl_aes_cbc::openssl_aes_cbc()
{
    //OpenSSL_add_all_algorithms();
}

openssl_aes_cbc::~openssl_aes_cbc()
{
    //OPENSSL_cleanup();
}

int openssl_aes_cbc::encrypt_128(const crypto_symmetric_key &key_in,
                             const uint8_t *msg_in,
                             uint32_t msg_len_in,
                             crypto_iv &iv_out,
                             uint8_t *msg_out)
{
    openssl_random r;
    EVP_CIPHER_CTX *cipher_ctx;
    int cipher_text_len = 0;
    int tmp_len = 0;
    int ret = -1;

    iv_out.iv_len = 12;
    r.get(iv_out.iv, iv_out.iv_len);

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        return -1;
    }

    ret = EVP_CipherInit_ex2(cipher_ctx, EVP_aes_128_cbc(),
                             key_in.key, iv_out.iv, 1, nullptr);
    if (ret != 1) {
        ret = -1;
        goto err;
    }

    ret= EVP_CipherUpdate(cipher_ctx, msg_out,
                          &cipher_text_len, msg_in, msg_len_in);
    if (ret != 1) {
        ret = -1;
        goto err;
    }

    ret = EVP_CipherFinal_ex(cipher_ctx, msg_out + cipher_text_len, &tmp_len);
    if (ret != 1) {
        ret = -1;
        goto err;
    }

    cipher_text_len += tmp_len;
    ret = cipher_text_len;

err:
    if (cipher_ctx) {
        EVP_CIPHER_CTX_free(cipher_ctx);
    }

    return ret;
}

int openssl_aes_cbc::decrypt_128(const crypto_symmetric_key &key_in,
                                 const uint8_t *enc_in,
                                 uint32_t enc_len_in,
                                 const crypto_iv &iv_in,
                                 uint8_t *msg_out)
{
    EVP_CIPHER_CTX *cipher_ctx;
    int deciphered_text_out = 0;
    int tmp_len = 0;
    int ret = -1;

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        return ret;
    }

    ret = EVP_CipherInit_ex2(cipher_ctx, EVP_aes_128_cbc(),
                             key_in.key, iv_in.iv, 0, nullptr);
    if (ret != 1) {
        ret = -1;
        goto err;
    }

    ret = EVP_CipherUpdate(cipher_ctx, msg_out,
                           &deciphered_text_out, enc_in, enc_len_in);
    if (ret != 1) {
        ret = -1;
        goto err;
    }

    ret = EVP_CipherFinal_ex(cipher_ctx, msg_out + deciphered_text_out, &tmp_len);
    if (ret != 1) {
        ret = -1;
        goto err;
    }

    deciphered_text_out += tmp_len;
    ret = deciphered_text_out;

err:
    if (cipher_ctx) {
        EVP_CIPHER_CTX_free(cipher_ctx);
    }

    return ret;
}

}
