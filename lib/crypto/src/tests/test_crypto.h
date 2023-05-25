#ifndef __NOS_CRYPTO_TEST_H__
#define __NOS_CRYPTO_TEST_H__

#include <crypto_factory.h>

namespace nos::crypto::tests {

int test_hash_functions(const nos::crypto::crypto_support &support);
int test_main();

}

#endif
