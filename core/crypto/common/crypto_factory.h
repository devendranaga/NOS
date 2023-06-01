#ifndef __NOS_CRYPTO_FACTORY_H__
#define __NOS_CRYPTO_FACTORY_H__

#include <memory>

#include <crypto_impl.h>
#include <crypto_keywraps.h>

namespace nos::crypto {

class crypto_factory {
    public:
        ~crypto_factory() { }
        static crypto_factory *instance() {
            static crypto_factory f;
            return &f;
        }

        std::shared_ptr<keywrap> create_keywrap(const crypto_impl &impl);
    private:
        explicit crypto_factory() { }
};

}

#endif
