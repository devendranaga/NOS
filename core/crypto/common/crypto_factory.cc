#include <memory>
#include <crypto_keywraps.h>

#include <nos_crypto_hmac_intf.h>
#include <nos_crypto_hkdf_intf.h>

#include <crypto_factory.h>

#include <mbedtls_keywraps.h>
#include <mbedtls_hmac.h>
#include <mbedtls_hkdf.h>
#include <mbedtls_hash.h>
#include <mbedtls_aes_cmac.h>

#include <openssl_hash.h>
#include <openssl_hmac.h>

namespace nos::crypto {

std::shared_ptr<keywrap> crypto_factory::create_keywrap(const crypto_impl &impl)
{
    if (impl == crypto_impl::openssl) {
    } else if (impl == crypto_impl::wolfssl) {
        return nullptr;
    } else if (impl == crypto_impl::mbedtls) {
        return std::make_shared<mbedtls_keywrap>();
    }

    return nullptr;
}

std::shared_ptr<hmac_intf> crypto_factory::create_hmac(const crypto_impl &impl)
{
    if (impl == crypto_impl::openssl) {
        return std::make_shared<openssl_hmac_intf>();
    } else if (impl == crypto_impl::wolfssl) {
        return nullptr;
    } else if (impl == crypto_impl::mbedtls) {
        return std::make_shared<mbedtls_hmac_intf>();
    }

    return nullptr;
}

std::shared_ptr<hkdf_intf> crypto_factory::create_hkdf(const crypto_impl &impl)
{
    if (impl == crypto_impl::openssl) {
        return nullptr;
    } else if (impl == crypto_impl::wolfssl) {
        return nullptr;
    } else if (impl == crypto_impl::mbedtls) {
        return std::make_shared<mbedtls_hkdf_intf>();
    }

    return nullptr;
}

std::shared_ptr<hash_function> crypto_factory::create_hash(const crypto_impl &impl)
{
    if (impl == crypto_impl::openssl) {
        return std::make_shared<openssl_hash_function>();
    } else if (impl == crypto_impl::wolfssl) {
        return nullptr;
    } else if (impl == crypto_impl::mbedtls) {
        return std::make_shared<mbedtls_hash_function>();
    }

    return nullptr;
}

std::shared_ptr<aes_cmac> crypto_factory::create_aes_cmac(const crypto_impl &impl)
{
    if (impl == crypto_impl::mbedtls) {
        return std::make_shared<mbedtls_aes_cmac>();
    }

    return nullptr;
}

}
