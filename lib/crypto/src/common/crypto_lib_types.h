#ifndef __CRYPTO_IMPL_H__
#define __CRYPTO_IMPL_H__

enum crypto_lib_type {
    CRYPTO_LIB_OPENSSL,
    CRYPTO_LIB_WOLFSSL,
    CRYPTO_LIB_MBEDTLS,
};

typedef enum crypto_lib_type crypto_lib_type_t;

#endif
