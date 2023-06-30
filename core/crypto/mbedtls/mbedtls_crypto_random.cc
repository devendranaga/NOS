#include <cstdlib>
#include <mbedtls/entropy.h>
#include <mbedtls_crypto_random.h>
#include <mbedtls/ctr_drbg.h>
#include <mutex>

namespace nos::crypto
{

mbedtls_random::mbedtls_random()
{
    uint8_t per[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,
        0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,
    };
    int ret;

    mbedtls_entropy_init(&entropy_ctx_);
    mbedtls_ctr_drbg_init(&drbg_ctx_);

    ret = mbedtls_ctr_drbg_seed(&drbg_ctx_,
                                mbedtls_entropy_func, &entropy_ctx_,
                                &per[0], sizeof(per));
    if (ret != 0) {
        throw std::runtime_error("mbedtls: cannot seed ctr_drbg");
    }
}

mbedtls_random::~mbedtls_random()
{
    mbedtls_ctr_drbg_free(&drbg_ctx_);
}

int mbedtls_random::get(uint8_t *data)
{
    int ret;

    ret = mbedtls_ctr_drbg_random(&drbg_ctx_, data, sizeof(uint8_t));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int mbedtls_random::get(uint16_t *data)
{
    int ret;

    ret = mbedtls_ctr_drbg_random(&drbg_ctx_, (uint8_t *)data, sizeof(uint16_t));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int mbedtls_random::get(uint32_t *data)
{
    int ret;

    ret = mbedtls_ctr_drbg_random(&drbg_ctx_, (uint8_t *)data, sizeof(uint32_t));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int mbedtls_random::get(uint64_t *data)
{
    int ret;

    ret = mbedtls_ctr_drbg_random(&drbg_ctx_, (uint8_t *)data, sizeof(uint64_t));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int mbedtls_random::get(uint8_t *data, uint32_t data_len)
{
    int ret;

    ret = mbedtls_ctr_drbg_random(&drbg_ctx_, data, data_len);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int mbedtls_random::write(const std::string &file, uint32_t data_len)
{
    uint8_t *data;
    FILE *fp;
    int ret;

    data = (uint8_t *)calloc(1, data_len);
    if (!data) {
        return -1;
    }
    ret = mbedtls_ctr_drbg_random(&drbg_ctx_, data, data_len);
    if (ret < 0) {
        free(data);
        return -1;
    }

    fp = fopen(file.c_str(), "wb");
    if (fp) {
        fwrite(data, data_len, 1, fp);
        fflush(fp);
    }

    fclose(fp);
    free(data);
    return 0;
}

}
