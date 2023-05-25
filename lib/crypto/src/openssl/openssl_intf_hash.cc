#include <openssl/evp.h>
#include <crypto_intf_hash.h>
#include <openssl_intf_hash.h>

namespace nos::crypto {

crypto_error openssl_hash::sha2_256(hash_input_buf &in,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha2_256(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha2_384(hash_input_buf &in,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha2_384(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha2_512(hash_input_buf &in,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha2_512(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_256(hash_input_buf &in,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_256(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_384(hash_input_buf &in,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_384(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_512(hash_input_buf &in,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::sha3_512(const std::string &in_file,
                                    hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::ripemd160(hash_input_buf &in,
                                     hash_output &out)
{
    return crypto_error::NO_ERROR;
}

crypto_error openssl_hash::ripemd160(const std::string &in_file,
                                     hash_output &out)
{
    return crypto_error::NO_ERROR;
}

}
