#ifndef __NOS_CRYPTO_HKDF_INTF_H__
#define __NOS_CRYPTO_HKDF_INTF_H__

#include <crypto_buffers.h>

namespace nos::crypto {

class hkdf_intf {
    public:
        explicit hkdf_intf() = default;
        ~hkdf_intf() = default;

        virtual int hkdf_hmac_sha256(crypto_context_buffer *salt,
                                     crypto_symmetric_key *ikm,
                                     crypto_context_buffer *ctx,
                                     crypto_symmetric_key *okm) = 0;
        virtual int hkdf_hmac_sha384(crypto_context_buffer *salt,
                                     crypto_symmetric_key *ikm,
                                     crypto_context_buffer *ctx,
                                     crypto_symmetric_key *okm) = 0;
        virtual int hkdf_hmac_sha512(crypto_context_buffer *salt,
                                     crypto_symmetric_key *ikm,
                                     crypto_context_buffer*ctx,
                                     crypto_symmetric_key *okm) = 0;
};

}

#endif
