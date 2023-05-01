#ifndef __CRYPTO_INTF_H__
#define __CRYPTO_INTF_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <crypto_lib_types.h>
#include <crypto_common.h>

typedef enum crypto_hash_type {
    CRYPTO_HASH_SHA2_256,
    CRYPTO_HASH_SHA2_384,
    CRYPTO_HASH_SHA2_512,
} crypto_hash_type_t;

typedef struct crypto_hash_in {
    crypto_hash_type_t  hash_type;
    uint8_t             *buf;
    uint32_t            buf_size;
    const char          *filename;
} crypto_hash_in_t;

#define CRYPTO_HASH_BUF_PREPARE(__hash_in, __hash_type, __buf, __buf_size) { \
    (__hash_in)->hash_type = __hash_type; \
    (__hash_in)->buf = __buf; \
    (__hash_in)->buf_size = __buf_size; \
    (__hash_in)->filename = NULL; \
}

#define CRYPTO_HASH_FILE_PREPARE(__hash_in, __hash_type, __filename) { \
    (__hash_in)->hash_type = __hash_type; \
    (__hash_in)->buf = 0; \
    (__hash_in)->buf_size = 0; \
    (__hash_in)->filename = __filename; \
}

typedef struct crypto_hash_out {
    uint8_t     hash[64];
    uint32_t    hash_len;
} crypto_hash_out_t;

#define CRYPTO_HASH_OUT_PREPARE(__hash_out) { \
    memset((__hash_out)->hash, 0, sizeof((__hash_out)->hash)); \
    (__hash_out)->hash_len = 0; \
}

typedef struct crypto_hash_intf {
    int (*hash)(crypto_hash_in_t *hash_in,
                crypto_hash_out_t *hash_out);
} crypto_hash_intf_t;

typedef struct crypto_mac_intf {
    int (*generate)(const char *keyfile,
                    const char *buf_in, uint32_t buf_in_size);
    bool (*verify)(const char *keyfile,
                   const char *buf_in, uint32_t buf_in_size);
} crypto_mac_intf_t;

typedef struct crypto_intf {
    crypto_hash_intf_t *hash_intf;
    crypto_mac_intf_t  *mac_intf;
} crypto_intf_t;

typedef struct crypto_intf_list {
    crypto_lib_type_t       type;
    crypto_intf_t           *intf;
    struct crypto_intf_list *next;
} crypto_intf_list_t;

typedef struct crypto_intf_context {
    crypto_intf_list_t *intf_h;
    crypto_intf_list_t *intf_t;
} crypto_intf_context_t;

int init_crypto_intf();
int register_crypto_intf(crypto_lib_type_t type, crypto_intf_t *intf);

int crypto_hash(crypto_hash_in_t *hash_in,
                crypto_hash_out_t *hash_out);

#endif
