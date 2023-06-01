#ifndef __NOS_CRYPTO_MBEDTLS_KEYWRAPS_H__
#define __NOS_CRYPTO_MBEDTLS_KEYWRAPS_H__

#include <string>
#include <crypto_buffers.h>
#include <crypto_keywraps.h>

namespace nos::crypto {

class mbedtls_keywrap : public keywrap {
    public:
        explicit mbedtls_keywrap() = default;
        ~mbedtls_keywrap() = default;

        int wrap(const std::string &kek,
                         const std::string &tbw_key,
                         const std::string &wrapped_key);
        int unwrap(const std::string &kek,
                           const std::string &wrapped_key,
                           const std::string &unwrapped_key);
        int wrap(const crypto_symmetric_key &kek,
                         crypto_symmetric_key &tbw_key,
                         crypto_symmetric_key &wrapped_key);
        int unwrap(const crypto_symmetric_key &kek,
                           crypto_symmetric_key &wrapped_key,
                           crypto_symmetric_key &unwrapped_key);
};

}

#endif
