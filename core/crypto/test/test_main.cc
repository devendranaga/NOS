#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>

int test_keywrap();

int test_hmac();

int test_hkdf();

int test_hash();

int main()
{
    int ret;

    ret = test_hash();
    if (ret != 0) {
        return -1;
    }

    ret = test_keywrap();
    if (ret != 0) {
        return -1;
    }

    ret = test_hmac();
    if (ret != 0) {
        return -1;
    }

    ret = test_hkdf();
    if (ret != 0) {
        return -1;
    }

    return 0;
}