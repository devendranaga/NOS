#include <openssl/evp.h>
#include <openssl_hash.h>

namespace nos::crypto
{

const static struct hash_str_map {
    hash_function_types type;
    const char *str;
} hash_str_list[] = {
    {hash_function_types::SHA2_256, "SHA256"},
    {hash_function_types::SHA2_384, "SHA384"},
    {hash_function_types::SHA2_512, "SHA512"},
    {hash_function_types::SHA3_256, "SHA3-256"},
    {hash_function_types::SHA3_384, "SHA3-384"},
    {hash_function_types::SHA3_512, "SHA3-512"},
};

static const char *get_hash_str(hash_function_types type)
{
    for (uint32_t i = 0; i < sizeof(hash_str_list) / sizeof(hash_str_list[0]); i ++) {
        if (hash_str_list[i].type == type) {
            return hash_str_list[i].str;
        }
    }

    return nullptr;
}

int openssl_hash_function::hash(const hash_function_types hf_type,
                                const uint8_t *buf, uint32_t buf_size,
                                crypto_hash_buffer &hash)
{
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
    const char *hash_name;
    int ret;

    hash_name = get_hash_str(hf_type);
    if (!hash_name) {
        return -1;
    }

    md = EVP_get_digestbyname(hash_name);
    if (!md) {
        return -1;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return -1;
    }

    ret = EVP_DigestInit_ex2(md_ctx, md, nullptr);
    if (ret == 0) {
        return -1;
    }

    ret = EVP_DigestUpdate(md_ctx, buf, buf_size);
    if (ret == 0) {
        return -1;
    }

    ret = EVP_DigestFinal_ex(md_ctx, hash.hash, &hash.hash_len);
    if (ret == 0) {
        return -1;
    }

    EVP_MD_CTX_free(md_ctx);

    return 0;
}

}
