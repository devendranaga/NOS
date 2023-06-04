#ifndef __NOS_CRYPTO_HASH_INTF_H__
#define __NOS_CRYPTO_HASH_INTF_H__

namespace nos::crypto {

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

}

#endif
