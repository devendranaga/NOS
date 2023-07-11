#ifndef __NOS_MBEDTLS_AES_CBC_H__
#define __NOS_MBEDTLS_AES_CBC_H__

#include <crypto_buffers.h>
#include <nos_crypto_aes_cbc.h>

namespace nos::crypto
{

class mbedtls_aes_cbc : public aes_cbc {
    public:
        explicit mbedtls_aes_cbc();
        ~mbedtls_aes_cbc();

        int encrypt_128(const crypto_symmetric_key &key_in,
                    const uint8_t *msg_in,
                    uint32_t msg_len_in,
                    crypto_iv &iv_out,
                    uint8_t *msg_out);
        int decrypt_128(const crypto_symmetric_key &key_in,
                    const uint8_t *enc_in,
                    uint32_t enc_len_in,
                    const crypto_iv &iv_in,
                    uint8_t *msg_out);
        int encrypt_192(const crypto_symmetric_key &key_in,
                            const uint8_t *msg_in,
                            uint32_t msg_len_in,
                            crypto_iv &iv_out,
                            uint8_t *msg_out);
        int decrypt_192(const crypto_symmetric_key &key_in,
                            const uint8_t *enc_in,
                            uint32_t enc_len_in,
                            const crypto_iv &iv_in,
                            uint8_t *msg_out);
        int encrypt_256(const crypto_symmetric_key &key_in,
                            const uint8_t *msg_in,
                            uint32_t msg_len_in,
                            crypto_iv &iv_out,
                            uint8_t *msg_out);
        int decrypt_256(const crypto_symmetric_key &key_in,
                            const uint8_t *enc_in,
                            uint32_t enc_len_in,
                            const crypto_iv &iv_in,
                            uint8_t *msg_out);
};

}

#endif

