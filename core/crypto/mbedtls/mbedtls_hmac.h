#ifndef __NOS_CRYPTO_MBEDTLS_HMAC_INTF_H__
#define __NOS_CRYPTO_MBEDTLS_HMAC_INTF_H__

#include <crypto_impl.h>
#include <crypto_buffers.h>
#include <nos_crypto_hash_intf.h>
#include <nos_crypto_hmac_intf.h>

namespace nos::crypto {

class mbedtls_hmac_intf : public hmac_intf {
    public:
        explicit mbedtls_hmac_intf() = default;
        ~mbedtls_hmac_intf() = default;

        int generate(hash_function_types hash_type,
                     crypto_symmetric_key &key_in,
                     uint8_t *msg_in, uint32_t msg_len,
                     crypto_mac_buffer &mac_out);
        int verify(hash_function_types hash_type,
                   crypto_symmetric_key &key_in,
                   uint8_t *msg_in, uint32_t msg_len,
                   crypto_mac_buffer &mac_out);
};

}

#endif
