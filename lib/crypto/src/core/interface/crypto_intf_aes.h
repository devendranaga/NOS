/**
 * @brief Implements interface to AES Crypto functions.
 * 
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
*/
#ifndef __NOS_CRYPTO_INTF_AES_H__
#define __NOS_CRYPTO_INTF_AES_H__

#include <cstring>
#include <stdint.h>
#include <string>
#include <crypto_error.h>
#include <crypto_intf_buf.h>

namespace nos::crypto {

enum aes_mode {
    /* CBC Mode. */
    AES_128_CBC,
    AES_192_CBC,
    AES_256_CBC,
    /* ECB Mode. */
    AES_128_ECB,
    AES_192_ECB,
    AES_256_ECB,
    /* GCM Mode. */
    AES_128_GCM,
    AES_192_GCM,
    AES_256_GCM,
    /* CCM Mode. */
    AES_128_CCM,
    AES_192_CCM,
    AES_256_CCM,
    /* CTR Mode. */
    AES_128_CTR,
    AES_192_CTR,
    AES_256_CTR,
};

struct aes_plain_text_params {
    crypto_buf buf_in;
    aes_mode mode;
    std::string key;
};

struct aes_cipher_text_params {
    crypto_buf buf_out;
    uint32_t buf_out_len;
    crypto_buf iv_out;
    crypto_buf tag_out;
};

class aes {
    public:
        explicit aes() = default;
        ~aes() = default;

        virtual int encrypt_128(aes_plain_text_params &in,
                                aes_cipher_text_params &out) = 0;
        virtual int decrypt_128(aes_cipher_text_params &in,
                                aes_plain_text_params &out) = 0;
        
        virtual int encrypt_192(aes_plain_text_params &in,
                                aes_cipher_text_params &out) = 0;
        virtual int decrypt_192(aes_cipher_text_params &in,
                                aes_plain_text_params &out) = 0;
        
        virtual int encrypt_256(aes_plain_text_params &in,
                                aes_cipher_text_params &out) = 0;
        virtual int decrypt_256(aes_cipher_text_params &in,
                                aes_plain_text_params &out) = 0;
};

}

#endif
