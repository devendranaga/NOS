#ifndef __NOS_CRYPTO_AES_CMAC_H__
#define __NOS_CRYPTO_AES_CMAC_H__

#include <crypto_buffers.h>

namespace nos::crypto
{

class aes_cmac {
    public:
        explicit aes_cmac() = default;
        ~aes_cmac() = default;

        virtual int sign_128(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac) = 0;
        virtual int verify_128(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac) = 0;
        
        virtual int sign_192(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac) = 0;
        virtual int verify_192(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac) = 0;

        virtual int sign_256(const uint8_t *buf, uint32_t buf_size,
                             const crypto_symmetric_key &key,
                             crypto_mac_buffer &mac) = 0;
        virtual int verify_256(const uint8_t *buf, uint32_t buf_size,
                               const crypto_symmetric_key &key,
                               crypto_mac_buffer &mac) = 0;
};

}

#endif
