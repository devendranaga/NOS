#ifndef __NOS_CRYPTO_HASH_INTF_H__
#define __NOS_CRYPTO_HASH_INTF_H__

#include <crypto_buffers.h>

namespace nos::crypto
{

enum hash_function_types {
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    RIPEMD160,
    SHAKE128,
    SHAKE256,
};

class hash_function {
    public:
        explicit hash_function() = default;
        ~hash_function() = default;

        virtual int hash(const hash_function_types hf_type,
                         const uint8_t *buf, uint32_t buf_size,
                         crypto_hash_buffer &hash) = 0;
};

}

#endif
