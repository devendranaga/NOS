#ifndef __NOS_CRYPTO_OPENSSL_HASH_INTF_H__
#define __NOS_CRYPTO_OPENSSL_HASH_INTF_H__

#include <crypto_buffers.h>
#include <nos_crypto_hash_intf.h>

namespace nos::crypto
{

class openssl_hash_function : public hash_function {
    public:
        explicit openssl_hash_function() = default;
        ~openssl_hash_function() = default;

        int hash(const hash_function_types hf_type,
                         const uint8_t *buf, uint32_t buf_size,
                         crypto_hash_buffer &hash);
};

}

#endif
