#ifndef __NOS_CRYPTO_RANDOM_H__
#define __NOS_CRYPTO_RANDOM_H__

#include <stdint.h>
#include <string>

namespace nos::crypto
{

class random {
    public:
        explicit random() = default;
        ~random() = default;

        virtual int get(uint8_t *data) = 0;
        virtual int get(uint16_t *data) = 0;
        virtual int get(uint32_t *data) = 0;
        virtual int get(uint64_t *data) = 0;
        virtual int get(uint8_t *data, uint32_t data_len) = 0;
        virtual int write(const std::string &file, uint32_t data_len) = 0;
};

}

#endif

