/**
 * @brief Implements interface to Hash functions.
 * 
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
*/
#ifndef __NOS_CRYPTO_INTF_HASH_H__
#define __NOS_CRYPTO_INTF_HASH_H__

#include <cstring>
#include <stdint.h>
#include <string>
#include <crypto_error.h>

namespace nos::crypto {

struct hash_input_buf {
    const uint8_t *buf;
    uint32_t buf_size;

    explicit hash_input_buf() { }
    explicit hash_input_buf(const uint8_t *buf_in, uint32_t buf_size_in): 
                    buf(buf_in), buf_size(buf_size_in) { }
    ~hash_input_buf() { }
};

struct hash_output {
    uint8_t hash[64];
    uint32_t hash_size;

    explicit hash_output() { 
        std::memset(hash, 0, sizeof(hash));
        hash_size = 0;
    }
    ~hash_output() { }

    void get_hash(uint8_t *hash_in, uint32_t hash_len) {
        if ((hash_len > 0) && (hash_len <= hash_size)) {
            memcpy(hash_in, hash, hash_len);
        }
    }
};

class hash {
    public:
        explicit hash() = default;
        ~hash() = default;

        virtual crypto_error sha2_256(hash_input_buf &in,
                                      hash_output &out) = 0;
        virtual crypto_error sha2_256(const std::string &in_file,
                                      hash_output &out) = 0;
        virtual crypto_error sha2_384(hash_input_buf &in,
                                      hash_output &out) = 0;
        virtual crypto_error sha2_384(const std::string &in_file,
                                      hash_output &out) = 0;
        virtual crypto_error sha2_512(hash_input_buf &in,
                                      hash_output &out) = 0;
        virtual crypto_error sha2_512(const std::string &in_file,
                                      hash_output &out) = 0;
        virtual crypto_error sha3_256(hash_input_buf &in,
                                      hash_output &out) = 0;
        virtual crypto_error sha3_256(const std::string &in_file,
                                      hash_output &out) = 0;
        virtual crypto_error sha3_384(hash_input_buf &in,
                                      hash_output &out) = 0;
        virtual crypto_error sha3_384(const std::string &in_file,
                                      hash_output &out) = 0;
        virtual crypto_error sha3_512(hash_input_buf &in,
                                      hash_output &out) = 0;
        virtual crypto_error sha3_512(const std::string &in_file,
                                      hash_output &out) = 0;
        virtual crypto_error ripemd160(hash_input_buf &in,
                                       hash_output &out) = 0;
        virtual crypto_error ripemd160(const std::string &in_file,
                                       hash_output &out) = 0;
};

}

#endif
