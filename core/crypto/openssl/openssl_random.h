#ifndef __NOS_OPENSSL_RANDOM_H__
#define __NOS_OPENSSL_RANDOM_H__

#include <stdint.h>
#include <string>
#include <nos_crypto_random.h>

namespace nos::crypto
{

class openssl_random : public random {
    public:
        explicit openssl_random();
        ~openssl_random();

        int get(uint8_t *data);
        int get(uint16_t *data);
        int get(uint32_t *data);
        int get(uint64_t *data);
        int get(uint8_t *data, uint32_t data_len);
        int write(const std::string &file, uint32_t data_len);
};

}

#endif

