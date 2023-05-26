#ifndef __NOS_CRYPTO_ERROR_H__
#define __NOS_CRYPTO_ERROR_H__

namespace nos::crypto {

enum class crypto_error {
    SHA2_256_FAILURE,
    SHA2_384_FAILURE,
    SHA2_512_FAILURE,
    RIPEMD160_FAILURE,
    INVALID_INPUT,
    NO_ERROR,
};

}

#endif
