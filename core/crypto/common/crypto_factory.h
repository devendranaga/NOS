#ifndef __NOS_CRYPTO_FACTORY_H__
#define __NOS_CRYPTO_FACTORY_H__

#include <memory>

#include <crypto_impl.h>
#include <crypto_keywraps.h>
#include <nos_crypto_hmac_intf.h>
#include <nos_crypto_hkdf_intf.h>
#include <nos_crypto_hash_intf.h>
#include <nos_crypto_aes_cmac.h>
#include <nos_crypto_aes_cbc.h>
#include <nos_crypto_aes_xts.h>

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
        std::shared_ptr<aes_cmac> create_aes_cmac(const crypto_impl &impl);
        std::shared_ptr<aes_cbc> create_aes_cbc(const crypto_impl &impl);
        std::shared_ptr<aes_xts> create_aes_xts(const crypto_impl &impl);
    private:
        explicit crypto_factory() { }
};

}

#endif
