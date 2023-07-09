#include <openssl/cmac.h>
#include <crypto_buffers.h>
#include <nos_crypto_aes_cmac.h>
#include <openssl_cmac.h>

namespace nos::crypto
{

int openssl_aes_cmac::sign_128(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac)
{
    return -1;
}

int openssl_aes_cmac::verify_128(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac)
{
    return -1;
}

int openssl_aes_cmac::sign_192(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac)
{
    return -1;
}

int openssl_aes_cmac::verify_192(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac)
{
    return -1;
}

int openssl_aes_cmac::sign_256(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac)
{
    return -1;
}

int openssl_aes_cmac::verify_256(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac)
{
    return -1;
}

}
