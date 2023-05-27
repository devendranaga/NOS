
/**
 * @brief Implements interface to Crypto keygen functions.
 * 
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
*/
#ifndef __NOS_CRYPTO_INTF_KEYGEN_H__
#define __NOS_CRYPTO_INTF_KEYGEN_H__

#include <cstring>
#include <stdint.h>
#include <string>
#include <crypto_error.h>

namespace nos::crypto {

class crypto_keygen {
    public:
        explicit crypto_keygen() = default;
        ~crypto_keygen() = default;

        virtual crypto_error get_aes_key(uint8_t *buf_out, uint32_t buf_out_len) = 0;
        virtual crypto_error get_aes_key(const std::string &key, uint32_t key_len) = 0;
        virtual crypto_error get_rsa_key(const std::string &priv, const std::string &pub) = 0;
};

}

#endif
