#include <test_crypto.h>

namespace nos::crypto::tests {

int test_main(const nos::crypto::crypto_support &support)
{
    int ret;

    ret = test_hash_functions(support);

    return ret;
}

}

int main()
{
    int ret;

    ret = nos::crypto::tests::test_main(nos::crypto::crypto_support::OpenSSL);

    return ret;
}
