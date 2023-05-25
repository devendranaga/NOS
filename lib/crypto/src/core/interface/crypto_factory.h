#include <memory>
#include <crypto_support.h>
#include <crypto_intf_hash.h>

namespace nos::crypto::crypto_factory {

std::unique_ptr<hash> get_hash_intf(const crypto_support &support);

}
