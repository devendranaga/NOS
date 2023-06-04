#ifndef __NOS_CRYPTO_HMAC_INTF_H__
#define __NOS_CRYPTO_HMAC_INTF_H__

#include <crypto_impl.h>
#include <crypto_buffers.h>
#include <nos_crypto_hash_intf.h>

namespace nos::crypto {

class hmac_intf {
    public:
        explicit hmac_intf() = default;
        ~hmac_intf() = default;

        virtual int generate(hash_function_types hash_type,
                             crypto_symmetric_key &key_in,
                             uint8_t *msg_in, uint32_t msg_len,
                             crypto_mac_buffer &mac_out) = 0;
        virtual int verify(hash_function_types hash_type,
                           crypto_symmetric_key &key_in,
                           uint8_t *msg_in, uint32_t msg_len,
                           crypto_mac_buffer &mac_out) = 0;
};

}

#endif
