#ifndef __CRYPTO_BUFFERS_H__
#define __CRYPTO_BUFFERS_H__

#include <cstring>
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
    explicit crypto_symmetric_key(uint8_t *key_buf, uint32_t key_buf_len) {
        std::memcpy(key, key_buf, key_buf_len);
        key_len = key_buf_len;
    }

    int write_key(const std::string &key_f);
};

struct crypto_iv {
    uint8_t iv[16];
    uint8_t iv_len;

    explicit crypto_iv() {
        std::memset(iv, 0, sizeof(iv));
        iv_len = 0;
    }
    ~crypto_iv() { }
    explicit crypto_iv(uint8_t *iv_in, uint8_t iv_in_len) {
        std::memcpy(iv, iv_in, iv_in_len);
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
    uint32_t hash_len;

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

struct crypto_mac_buffer {
    uint8_t signature[128];
    uint32_t signature_len;

    explicit crypto_mac_buffer() {
        memset(signature, 0, sizeof(signature));
        signature_len = 0;
    }
    ~crypto_mac_buffer() { }
    explicit crypto_mac_buffer(uint8_t *mac_in, uint32_t mac_len) {
        memcpy(signature, mac_in, mac_len);
        signature_len = mac_len;
    }
};

struct crypto_context_buffer {
    uint8_t context[128];
    uint32_t context_len;

    explicit crypto_context_buffer() {
        memset(context, 0, sizeof(context));
        context_len = 0;
    }
    ~crypto_context_buffer() { }
    explicit crypto_context_buffer(uint8_t *ctx, uint32_t ctx_len) {
        memcpy(context, ctx, ctx_len);
        context_len = ctx_len;
    }
};

}

#endif
