/**
 * @brief - Implements Hash interface.
 * 
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __AOS_CRYPTO_HASH_INTF_H__
#define __AOS_CRYPTO_HASH_INTF_H__

#include <stdint.h>
#include <crypto_lib_types.h>

/* Crypto hash type. */
typedef enum crypto_hash_type {
    CRYPTO_HASH_SHA2_256 = 0,
    CRYPTO_HASH_SHA2_384,
    CRYPTO_HASH_SHA2_512,
    CRYPTO_HASH_SHA3_256,
    CRYPTO_HASH_SHA3_384,
    CRYPTO_HASH_SHA3_512,
    CRYPTO_HASH_SHAKE128,
    CRYPTO_HASH_SHAKE256,
    CRYPTO_HASH_RIPEMD160,
} crypto_hash_type_t;

typedef struct crypto_hash_in {
    /* One of the supported libraries. */
    crypto_lib_type_t   lib_type;
    crypto_hash_type_t  hash_type;
    uint8_t             *buf;
    uint32_t            buf_size;
    const char          *filename;
} crypto_hash_in_t;

/* Prepare the Hash parameter buffer. */
#define CRYPTO_HASH_BUF_PREPARE(__hash_in, __lib_type, __hash_type, __buf, __buf_size) { \
    (__hash_in)->lib_type = __lib_type; \
    (__hash_in)->hash_type = __hash_type; \
    (__hash_in)->buf = __buf; \
    (__hash_in)->buf_size = __buf_size; \
    (__hash_in)->filename = NULL; \
}

/* Prepare the Hash parameter buffer for file hashing. */
#define CRYPTO_HASH_FILE_PREPARE(__hash_in, __lib_type, __hash_type, __filename) { \
    (__hash_in)->lib_type = __lib_type; \
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

/**
 * @brief - Generate the Hash.
 * 
 * @param[in] hash_in : input hash parameter data.
 * @param[out] hash_out : output hash parameter data.
 * 
 * @return 0 on success -1 on failure.
*/
int crypto_hash(crypto_hash_in_t *hash_in,
                crypto_hash_out_t *hash_out);

/**
 * @brief - Get Hash string of the hash type.
 * 
 * @param[in] type : Hash type.
 * 
 * @return string format of hash type.
*/
const char *crypto_hash_string(crypto_hash_type_t type);

#endif
