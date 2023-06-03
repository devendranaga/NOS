#ifndef __NOS_CRYPTO_IMPL_H__
#define __NOS_CRYPTO_IMPL_H__

namespace nos::crypto {

enum crypto_impl {
    openssl,
    wolfssl,
    mbedtls,
};

}

#endif
