#include <crypto_support.h>
#include <crypto_error.h>
#include <crypto_intf_hash.h>
#include <crypto_factory.h>
#include <openssl_intf_hash.h>

namespace nos::crypto::crypto_factory {

std::unique_ptr<hash> get_hash_intf(const crypto_support &support)
{
    if (support == crypto_support::OpenSSL) {
        return std::make_unique<openssl_hash>();
    }

    return nullptr;
}

}
