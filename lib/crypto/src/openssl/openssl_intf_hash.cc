#include <openssl/evp.h>
#include <crypto_intf_hash.h>
#include <openssl_intf_hash.h>

namespace nos::crypto {

static crypto_error hash_msg(hash_input_buf &in,
                             hash_output &out,
                             const EVP_MD *md)
{
    crypto_error err = crypto_error::SHA2_256_FAILURE;
    EVP_MD_CTX *md_ctx;
    int ret;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return err;
    }

    ret = EVP_DigestInit_ex(md_ctx, md, NULL);
    if (ret != 1) {
        goto free_md_ctx;
    }

    ret = EVP_DigestUpdate(md_ctx, in.buf, in.buf_size);
    if (ret != 1) {
        goto free_md_ctx;
    }

    ret = EVP_DigestFinal(md_ctx, out.hash, &out.hash_size);
    if (ret != 1) {
        goto free_md_ctx;
    }

    err = crypto_error::NO_ERROR;

free_md_ctx:
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }

    return err;
}

crypto_error openssl_hash::sha2_256(hash_input_buf &in,
                                    hash_output &out)
{
    return hash_msg(in, out, EVP_sha256());
}

crypto_error openssl_hash::sha2_256(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha2_384(hash_input_buf &in,
                                    hash_output &out)
{
    return hash_msg(in, out, EVP_sha384());
}

crypto_error openssl_hash::sha2_384(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha2_512(hash_input_buf &in,
                                    hash_output &out)
{
    return hash_msg(in, out, EVP_sha512());
}

crypto_error openssl_hash::sha2_512(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_256(hash_input_buf &in,
                                    hash_output &out)
{
    return hash_msg(in, out, EVP_sha3_256());
}

crypto_error openssl_hash::sha3_256(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_384(hash_input_buf &in,
                                    hash_output &out)
{
    return hash_msg(in, out, EVP_sha3_384());
}

crypto_error openssl_hash::sha3_384(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_512(hash_input_buf &in,
                                    hash_output &out)
{
    return hash_msg(in, out, EVP_sha3_512());
}

crypto_error openssl_hash::sha3_512(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::ripemd160(hash_input_buf &in,
                                     hash_output &out)
{
    return hash_msg(in, out, EVP_ripemd160());
}

crypto_error openssl_hash::ripemd160(const std::string &in_file,
                                     hash_output &out)
{
    return crypto_error::NO_ERROR;
}

}
