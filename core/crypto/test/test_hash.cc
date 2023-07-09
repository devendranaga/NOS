#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>

static const struct hash_fn_map {
    nos::crypto::hash_function_types hf;
    const char *hf_str;
} hash_list[] = {
    {nos::crypto::hash_function_types::SHA2_256, "SHA2_256"},
    {nos::crypto::hash_function_types::SHA2_384, "SHA2_384"},
    {nos::crypto::hash_function_types::SHA2_512, "SHA2_512"},
    {nos::crypto::hash_function_types::SHA3_256, "SHA3_256"},
    {nos::crypto::hash_function_types::SHA3_384, "SHA3_384"},
    {nos::crypto::hash_function_types::SHA3_512, "SHA3_512"},
    {nos::crypto::hash_function_types::RIPEMD160, "RIPEMD160"},
    {nos::crypto::hash_function_types::SHAKE128, "SHAKE128"},
    {nos::crypto::hash_function_types::SHAKE256, "SHAKE256"},
};

int test_hash()
{
    uint8_t data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    };
    std::shared_ptr<nos::crypto::hash_function> hf;
    nos::crypto::crypto_hash_buffer hash_buf;
    int ret;

    hf = nos::crypto::crypto_factory::instance()->create_hash(
                        nos::crypto::crypto_impl::openssl);
    for (uint32_t i = 0; i < sizeof(hash_list) / sizeof(hash_list[0]); i ++) {
        ret = hf->hash(hash_list[i].hf, data, sizeof(data), hash_buf);
        if (ret < 0) {
            return -1;
        }

        printf("hash [%s]: ", hash_list[i].hf_str);
        for (uint32_t i = 0; i < hash_buf.hash_len ; i ++) {
            printf("%02x", hash_buf.hash[i]);
        }
        printf("\n");
    }

    return 0;
}
