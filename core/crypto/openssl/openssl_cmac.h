/**
 * @brief - Implements AES-CMAC.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __NOS_CRYPTO_OPENSSL_AES_CMAC_H__
#define __NOS_CRYPTO_OPENSSL_AES_CMAC_H__

#include <crypto_buffers.h>
#include <nos_crypto_aes_cmac.h>

namespace nos::crypto
{

class openssl_aes_cmac : public aes_cmac {
    public:
        explicit openssl_aes_cmac() = default;
        ~openssl_aes_cmac() = default;

        int sign_128(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac);
        int verify_128(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac);

        int sign_192(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac);
        int verify_192(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac);

        int sign_256(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac);
        int verify_256(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac);
};

}

#endif
