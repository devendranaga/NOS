#include <memory>
#include <crypto_keywraps.h>
#include <crypto_factory.h>
#include <mbedtls_keywraps.h>

namespace nos::crypto {

std::shared_ptr<keywrap> crypto_factory::create_keywrap(const crypto_impl &impl)
{
    if (impl == crypto_impl::openssl) {
        return nullptr;
    } else if (impl == crypto_impl::wolfssl) {
        return nullptr;
    } else if (impl == crypto_impl::mbedtls) {
        return std::make_shared<mbedtls_keywrap>();
    }

    return nullptr;
}

}
