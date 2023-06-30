#ifndef __MBEDTLS_CRYPTO_RANDOM_H__
#define __MBEDTLS_CRYPTO_RANDOM_H__

#include <mutex>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <nos_crypto_random.h>

namespace nos::crypto
{

class mbedtls_random : public random {
    public:
        explicit mbedtls_random();
        ~mbedtls_random();

        int get(uint8_t *data);
        int get(uint16_t *data);
        int get(uint32_t *data);
        int get(uint64_t *data);
        int get(uint8_t *data, uint32_t data_len);
        int write(const std::string &file, uint32_t data_len);

    private:
        mbedtls_entropy_context entropy_ctx_;
        mbedtls_ctr_drbg_context drbg_ctx_;
        std::mutex lock_;
};

}

#endif
