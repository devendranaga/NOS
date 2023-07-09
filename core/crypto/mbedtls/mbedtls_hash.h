#ifndef __NOS_CRYPTO_MBEDTLS_HASH_INTF_H__
#define __NOS_CRYPTO_MBEDTLS_HASH_INTF_H__

#include <nos_crypto_hash_intf.h>

namespace nos::crypto
{

class mbedtls_hash_function : public hash_function {
    public:
        explicit mbedtls_hash_function() = default;
        ~mbedtls_hash_function() = default;

        int hash(const hash_function_types hf_type,
                 const uint8_t *buf, uint32_t buf_size,
                 crypto_hash_buffer &hash);
};

}

#endif
