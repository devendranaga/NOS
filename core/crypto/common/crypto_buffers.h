#ifndef __CRYPTO_BUFFERS_H__
#define __CRYPTO_BUFFERS_H__

#include <stdint.h>
#include <string.h>
#include <string>

namespace nos::crypto {

struct crypto_symmetric_key {
    uint8_t key[64];
    uint32_t key_len;

    explicit crypto_symmetric_key() {
        memset(key, 0, sizeof(key));
        key_len = 0;
    }
    ~crypto_symmetric_key() { }
    explicit crypto_symmetric_key(const std::string &key_f);

    int write_key(const std::string &key_f);
};

struct crypto_iv {
    uint8_t iv[16];
    uint8_t iv_len;

    explicit crypto_iv() { 
        memset(iv, 0, sizeof(iv));
        iv_len = 0;
    }
    ~crypto_iv() { }
    explicit crypto_iv(uint8_t *iv_in, uint8_t iv_in_len) {
        memcpy(iv, iv_in, iv_in_len);
        iv_len = iv_in_len;
    }
};

struct crypto_tag {
    uint8_t tag[16];
    uint8_t tag_len;

    explicit crypto_tag() {
        memset(tag, 0, sizeof(tag));
        tag_len = 0;
    }
    ~crypto_tag() { }
    explicit crypto_tag(uint8_t *tag_in, uint8_t tag_in_len) {
        memcpy(tag, tag_in, tag_in_len);
        tag_len = tag_in_len;
    }
};

struct crypto_hash_buffer {
    uint8_t hash[64];
    uint8_t hash_len;

    explicit crypto_hash_buffer() {
        memset(hash, 0, sizeof(hash));
        hash_len = 0;
    }
    ~crypto_hash_buffer() { }
    explicit crypto_hash_buffer(uint8_t *hash_in, uint8_t hash_in_len) {
        memcpy(hash, hash_in, hash_in_len);
        hash_len = hash_in_len;
    }
};

}

#endif
