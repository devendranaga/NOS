#ifndef __NOS_MBEDTLS_AES_XTS_H__
#define __NOS_MBEDTLS_AES_XTS_H__

#include <crypto_buffers.h>
#include <nos_crypto_aes_xts.h>

namespace nos::crypto
{

class mbedtls_aes_xts : public aes_xts {
    public:
        explicit mbedtls_aes_xts();
        ~mbedtls_aes_xts();

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

