#include <mbedtls_hash.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

namespace nos::crypto
{

static int sha2_256(const uint8_t *buf, uint32_t buf_size,
                    crypto_hash_buffer &hash)
{
    int ret;
    
    ret = mbedtls_sha256(buf, buf_size, hash.hash, 0);
    if (ret != 0) {
        return -1;
    }

    hash.hash_len = 32;
    return 0;
}

static int sha2_384(const uint8_t *buf, uint32_t buf_size,
                    crypto_hash_buffer &hash)
{
    int ret;

    ret = mbedtls_sha512(buf, buf_size, hash.hash, 1);
    if (ret != 0) {
        return -1;
    }

    hash.hash_len = 48;
    return 0;
}

static int sha2_512(const uint8_t *buf, uint32_t buf_size,
                    crypto_hash_buffer &hash)
{
    int ret;

    ret = mbedtls_sha512(buf, buf_size, hash.hash, 0);
    if (ret != 0) {
        return -1;
    }

    hash.hash_len = 64;
    return 0;
}

int mbedtls_hash_function::hash(const hash_function_types hf_type,
                                const uint8_t *buf, uint32_t buf_size,
                                crypto_hash_buffer &hash)
{
    switch (hf_type) {
        case hash_function_types::SHA2_256:
            return sha2_256(buf, buf_size, hash);
        case hash_function_types::SHA2_384:
            return sha2_384(buf, buf_size, hash);
        case hash_function_types::SHA2_512:
            return sha2_512(buf, buf_size, hash);
        default:
            return -1;
    }

    return -1;
}

}
