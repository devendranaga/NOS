#include <stdio.h>
#include <crypto_intf.h>
#include <aos_core.h>

struct crypto_hash_test_vectors {
    crypto_lib_type_t type;
    const char *hash_name;
    uint8_t msg[1024];
    uint32_t msg_len;
    uint8_t hash[64];
    uint32_t hash_len;
} hash_test_vectors[] = {
    {
        .type = CRYPTO_LIB_OPENSSL,
        .hash_name = "SHA256",
        .msg = {
            0x00,
        },
        .msg_len = 1,
        .hash = {
            0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98,
            0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
            0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
            0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
        },
        .hash_len = 32,
    },
    {
        .type = CRYPTO_LIB_MBEDTLS,
        .hash_name = "SHA256",
        .msg = {
            0x00,
        },
        .msg_len = 1,
        .hash = {
            0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98,
            0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
            0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
            0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
        },
        .hash_len = 32,
    }
};

static int crypto_hash_tests()
{
    crypto_hash_in_t hash_in;
    crypto_hash_out_t hash_out;
    int i;
    int j;
    bool result;
    int ret;

    for (i = 0; i < sizeof(hash_test_vectors) / sizeof(hash_test_vectors[0]); i ++) {
        CRYPTO_HASH_BUF_PREPARE(&hash_in, hash_test_vectors[i].type,
                                CRYPTO_HASH_SHA2_256,
                                hash_test_vectors[i].msg,
                                hash_test_vectors[i].msg_len);
        CRYPTO_HASH_OUT_PREPARE(&hash_out);

        ret = crypto_hash(&hash_in, &hash_out);
        if (ret < 0) {
            return -1;
        } else {
            aos_hexdump_crypto(hash_test_vectors[i].hash_name,
                               hash_out.hash, hash_out.hash_len);
            if (crypto_safe_memcmp(hash_test_vectors[i].hash,
                                   hash_out.hash, hash_out.hash_len) == 0) {
                result = true;
            } else {
                result = false;
            }

            printf("Type [%s] [%s] test %s \n",
                            crypto_get_lib_type_str(hash_test_vectors[i].type),
                            hash_test_vectors[i].hash_name,
                            result ? "Pass" : "Fail");
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret;

    ret = init_crypto_intf();
    if (ret != 0) {
        return -1;
    }

    crypto_hash_tests();
}
