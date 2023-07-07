#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls_aes_cmac.h>

namespace nos::crypto
{

static int sign(const mbedtls_cipher_info_t *cipher,
                const uint8_t *buf, uint32_t buf_size,
                const crypto_symmetric_key &key,
                crypto_mac_buffer &mac)
{
    int ret;

    ret = mbedtls_cipher_cmac(cipher, key.key, key.key_len * 8,
                              buf, buf_size, mac.signature);
    if (ret != 0) {
        return -1;
    }

    mac.signature_len = 16;
    return 0;
}

static int verify(const mbedtls_cipher_info_t *cipher,
                  const uint8_t *buf, uint32_t buf_size,
                  const crypto_symmetric_key &key,
                  crypto_mac_buffer &mac)
{
    crypto_mac_buffer sig_buf;
    int ret;

    ret = mbedtls_cipher_cmac(cipher, key.key, key.key_len * 8,
                              buf, buf_size, sig_buf.signature);
    if (ret != 0) {
        return -1;
    }

    if (memcmp(mac.signature, sig_buf.signature, mac.signature_len) == 0) {
        return 0;
    }

    return -1;
}

int mbedtls_aes_cmac::sign_128(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac)
{
    return sign(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB),
                buf, buf_size, key, mac);
}

int mbedtls_aes_cmac::verify_128(const uint8_t *buf, uint32_t buf_size,
                                 const crypto_symmetric_key &key,
                                 crypto_mac_buffer &mac)
{
    return verify(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB),
                  buf, buf_size, key, mac);
}

int mbedtls_aes_cmac::sign_192(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac)
{
    return sign(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB),
                buf, buf_size, key, mac);
}

int mbedtls_aes_cmac::verify_192(const uint8_t *buf, uint32_t buf_size,
                                 const crypto_symmetric_key &key,
                                 crypto_mac_buffer &mac)
{
    return verify(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB),
                  buf, buf_size, key, mac);
}

int mbedtls_aes_cmac::sign_256(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac)
{
    return sign(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB),
                buf, buf_size, key, mac);
}

int mbedtls_aes_cmac::verify_256(const uint8_t *buf, uint32_t buf_size,
                                 const crypto_symmetric_key &key,
                                 crypto_mac_buffer &mac)
{
    return verify(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB),
                  buf, buf_size, key, mac);
}

}
