#ifndef __NOS_CRYPTO_FACTORY_H__
#define __NOS_CRYPTO_FACTORY_H__

#include <memory>

#include <crypto_impl.h>
#include <crypto_keywraps.h>
#include <nos_crypto_hmac_intf.h>
#include <nos_crypto_hkdf_intf.h>
#include <nos_crypto_hash_intf.h>

namespace nos::crypto {

class crypto_factory {
    public:
        ~crypto_factory() { }
        static crypto_factory *instance() {
            static crypto_factory f;
            return &f;
        }

        std::shared_ptr<keywrap> create_keywrap(const crypto_impl &impl);
        std::shared_ptr<hmac_intf> create_hmac(const crypto_impl &impl);
        std::shared_ptr<hkdf_intf> create_hkdf(const crypto_impl &impl);
        std::shared_ptr<hash_function> create_hash(const crypto_impl &impl);
    private:
        explicit crypto_factory() { }
};

}

#endif
