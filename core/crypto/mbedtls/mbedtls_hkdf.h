#ifndef __NOS_CRYPTO_MBEDTLS_HKDF_INTF_H__
#define __NOS_CRYPTO_MBEDTLS_HKDF_INTF_H__

#include <crypto_buffers.h>
#include <nos_crypto_hkdf_intf.h>

namespace nos::crypto
{

class mbedtls_hkdf_intf : public hkdf_intf {
    public:
        explicit mbedtls_hkdf_intf() = default;
        ~mbedtls_hkdf_intf() = default;

        int hkdf_hmac_sha256(crypto_context_buffer *salt,
                             crypto_symmetric_key *ikm,
                             crypto_context_buffer *ctx,
                             crypto_symmetric_key *okm);

        int hkdf_hmac_sha384(crypto_context_buffer *salt,
                             crypto_symmetric_key *ikm,
                             crypto_context_buffer *ctx,
                             crypto_symmetric_key *okm);

        int hkdf_hmac_sha512(crypto_context_buffer *salt,
                             crypto_symmetric_key *ikm,
                             crypto_context_buffer*ctx,
                             crypto_symmetric_key *okm);
};

}

#endif
