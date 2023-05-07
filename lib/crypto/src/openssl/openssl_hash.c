/**
 * @brief - Implements the OpenSSL crypto hash function.
 * 
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
*/
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <nos_core.h>
#include <crypto_intf.h>
#include <openssl_crypto_common.h>

static const EVP_MD *get_hash_fn(crypto_hash_type_t hash_type)
{
    switch (hash_type) {
        case CRYPTO_HASH_SHA2_256:
            return EVP_sha256();
        case CRYPTO_HASH_SHA2_384:
            return EVP_sha384();
        case CRYPTO_HASH_SHA2_512:
            return EVP_sha512();
        case CRYPTO_HASH_SHA3_256:
            return EVP_sha3_256();
        case CRYPTO_HASH_SHA3_384:
            return EVP_sha3_384();
        case CRYPTO_HASH_SHA3_512:
            return EVP_sha3_512();
        case CRYPTO_HASH_RIPEMD160:
            return EVP_ripemd160();
        case CRYPTO_HASH_SHAKE128:
            return EVP_shake128();
        case CRYPTO_HASH_SHAKE256:
            return EVP_shake256();
        default:
            return NULL;
    }

    return NULL;
}

static int openssl_hash_file(EVP_MD_CTX *md_ctx,
                             crypto_hash_in_t *hash_in,
                             crypto_hash_out_t *hash_out)
{
    int fd;
    int ret;

    fd = nos_fileio_open(hash_in->filename, "rb");
    if (fd < 0) {
        return -1;
    }

    while (1) {
        uint8_t msg[1024];

        ret = nos_fileio_read(fd, (char *)msg, sizeof(msg));
        if (ret <= 0) {
            break;
        }

        ret = EVP_DigestUpdate(md_ctx, msg, ret);
        LIBACORE_OPENSSL_RET_CHECK(ret);
    }

    ret = EVP_DigestFinal_ex(md_ctx, hash_out->hash, &hash_out->hash_len);
    LIBACORE_OPENSSL_RET_CHECK(ret);

    nos_fileio_close(fd);

    return 0;
}

static int openssl_hash_buf(EVP_MD_CTX *md_ctx,
                            crypto_hash_in_t *hash_in,
                            crypto_hash_out_t *hash_out)
{
    int ret;

    ret = EVP_DigestUpdate(md_ctx, hash_in->buf, hash_in->buf_size);
    LIBACORE_OPENSSL_RET_CHECK(ret);

    ret = EVP_DigestFinal_ex(md_ctx, hash_out->hash, &hash_out->hash_len);
    LIBACORE_OPENSSL_RET_CHECK(ret);

    return ret;
}

int openssl_hash(crypto_hash_in_t *hash_in,
                 crypto_hash_out_t *hash_out)
{
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
    int ret;

    if (!hash_in || !hash_out) {
        return -1;
    }

    md = get_hash_fn(hash_in->hash_type);
    if (!md) {
        return -1;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return -1;
    }

    ret = EVP_DigestInit_ex(md_ctx, md, NULL);
    LIBACORE_OPENSSL_RET_CHECK(ret);

    if (hash_in->buf && (hash_in->buf_size > 0)) {
        ret = openssl_hash_buf(md_ctx, hash_in, hash_out);
    } else if (hash_in->buf && hash_in->filename) {
        ret = openssl_hash_file(md_ctx, hash_in, hash_out);
    } else {
        ret = -1;
    }

    EVP_MD_CTX_destroy(md_ctx);
    return ret;
}
