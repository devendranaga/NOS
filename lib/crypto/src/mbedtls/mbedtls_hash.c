#include <stdint.h>
#include <stdbool.h>
#include <mbedtls/sha256.h>
#include <crypto_intf.h>
#include <nos_core.h>

#define LIBACORE_MBEDTSL_RET_CHECK(__res) { \
    if (__res != 0) { \
        return -1; \
    } \
}

static int mbedtls_hash_sha2_256_buf(crypto_hash_in_t *hash_in,
                                     crypto_hash_out_t *hash_out)
{
    mbedtls_sha256_context sha256_ctx;
    int ret;

    ret = mbedtls_sha256_ret(hash_in->buf,
                             hash_in->buf_size, hash_out->hash, 0);
    LIBACORE_MBEDTSL_RET_CHECK(ret);

    hash_out->hash_len = 32;

    return ret;
}

static int mbedtls_hash_sha2_256_file(crypto_hash_in_t *hash_in,
                                      crypto_hash_out_t *hash_out)
{
    mbedtls_sha256_context sha256_ctx;
    int fd;
    int ret;

    fd = nos_fileio_open(hash_in->filename, "rb");
    if (fd < 0) {
        return -1;
    }

    mbedtls_sha256_init(&sha256_ctx);

    while (1) {
        uint8_t buf[1024];

        ret = nos_fileio_read(fd, buf, sizeof(buf));
        if (ret <= 0) {
            break;
        }

        (void)mbedtls_sha256_update_ret(&sha256_ctx, buf, ret);
    }

    ret = mbedtls_sha256_finish_ret(&sha256_ctx, hash_out->hash);
    hash_out->hash_len = 32;

    return ret;
}

static struct mbedtls_hash_info {
    crypto_hash_type_t type;
    int (*hash_buf)(crypto_hash_in_t *hash_in,
                    crypto_hash_out_t *hash_out);
    int (*hash_file)(crypto_hash_in_t *hash_in,
                     crypto_hash_out_t *hash_out);
} hash_list[] = {
    {CRYPTO_HASH_SHA2_256, mbedtls_hash_sha2_256_buf, NULL},
    {CRYPTO_HASH_SHA2_256, NULL, mbedtls_hash_sha2_256_file},
};

int mbedtls_hash(crypto_hash_in_t *hash_in,
                 crypto_hash_out_t *hash_out)
{
    int ret;
    int i;

    if (!hash_in || !hash_out) {
        return -1;
    }

    for (i = 0; i < sizeof(hash_list) / sizeof(hash_list[0]); i ++) {
        if (hash_list[i].type == hash_in->hash_type) {
            if (hash_in->buf && hash_list[i].hash_buf) {
                ret = hash_list[i].hash_buf(hash_in, hash_out);
                break;
            } else if (hash_in->filename && hash_list[i].hash_file) {
                ret = hash_list[i].hash_file(hash_in, hash_out);
                break;
            }
        }
    }

    return ret;
}
