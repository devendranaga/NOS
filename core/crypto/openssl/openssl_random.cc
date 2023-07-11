#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl_random.h>
#include <nos_core.h>

namespace nos::crypto
{

openssl_random::openssl_random()
{
    OpenSSL_add_all_algorithms();
}

openssl_random::~openssl_random()
{
    OPENSSL_cleanup();
}

int openssl_random::get(uint8_t *data)
{
    return RAND_bytes(data, sizeof(*data)) == 1;
}

int openssl_random::get(uint16_t *data)
{
    return RAND_bytes((uint8_t *)data, sizeof(*data)) == 1;
}

int openssl_random::get(uint32_t *data)
{
    return RAND_bytes((uint8_t *)data, sizeof(*data)) == 1;
}

int openssl_random::get(uint64_t *data)
{
    return RAND_bytes((uint8_t *)data, sizeof(*data)) == 1;
}

int openssl_random::get(uint8_t *data, uint32_t data_len)
{
    return RAND_bytes(data, data_len) == 1;
}

int openssl_random::write(const std::string &file, uint32_t data_len)
{
    nos::core::file_intf fi;
    uint8_t *data;
    int ret;

    ret = fi.create(file, nos::core::file_mode::MODE_SECURITY);
    if (ret < 0) {
        return -1;
    }

    data = (uint8_t *)calloc(1, data_len);
    if (!data) {
        return -1;
    }

    ret = RAND_bytes(data, data_len);
    if (ret != 1) {
        free(data);
        return -1;
    }

    ret = fi.write(data, data_len);
    if (ret < 0) {
        free(data);
        return -1;
    }

    free(data);

    fi.flush();
    fi.close();

    return 0;
}

}
