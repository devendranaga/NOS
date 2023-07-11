#ifndef __NOS_CRYPTO_AES_CBC_H__
#define __NOS_CRYPTO_AES_CBC_H__

#include <crypto_buffers.h>

namespace nos::crypto
{

class aes_cbc {
    public:
        explicit aes_cbc() = default;
        ~aes_cbc() = default;

        virtual int encrypt_128(const crypto_symmetric_key &key_in,
                            const uint8_t *msg_in,
                            uint32_t msg_len_in,
                            crypto_iv &iv_out,
                            uint8_t *msg_out) = 0;
        virtual int decrypt_128(const crypto_symmetric_key &key_in,
                            const uint8_t *enc_in,
                            uint32_t enc_len_in,
                            const crypto_iv &iv_in,
                            uint8_t *msg_out) = 0;
        virtual int encrypt_192(const crypto_symmetric_key &key_in,
                            const uint8_t *msg_in,
                            uint32_t msg_len_in,
                            crypto_iv &iv_out,
                            uint8_t *msg_out) = 0;
        virtual int decrypt_192(const crypto_symmetric_key &key_in,
                            const uint8_t *enc_in,
                            uint32_t enc_len_in,
                            const crypto_iv &iv_in,
                            uint8_t *msg_out) = 0;
        virtual int encrypt_256(const crypto_symmetric_key &key_in,
                            const uint8_t *msg_in,
                            uint32_t msg_len_in,
                            crypto_iv &iv_out,
                            uint8_t *msg_out) = 0;
        virtual int decrypt_256(const crypto_symmetric_key &key_in,
                            const uint8_t *enc_in,
                            uint32_t enc_len_in,
                            const crypto_iv &iv_in,
                            uint8_t *msg_out) = 0;
};

}

#endif

