#include <memory>
#include <crypto_intf_hash.h>
#include <crypto_factory.h>

namespace nos::crypto::tests {

int test_hash_functions(const nos::crypto::crypto_support &support)
{
    std::unique_ptr<hash> hash_impl;

    hash_impl = nos::crypto::crypto_factory::get_hash_intf(support);

    return 0;
}

}
