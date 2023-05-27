/**
 * @brief Implements interface to Crypto buffers.
 * 
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
*/
#ifndef __NOS_CRYPTO_INTF_BUF_H__
#define __NOS_CRYPTO_INTF_BUF_H__

#include <cstring>
#include <cstdlib>
#include <stdint.h>
#include <string>
#include <crypto_error.h>
#include <crypto_intf_buf.h>

namespace nos::crypto {

struct crypto_buf {
    uint8_t *in;
    uint32_t in_len;

    crypto_buf(uint8_t *in_buf, uint32_t in_buf_len) :
                    in(in_buf), in_len(in_buf_len) { }
    crypto_error allocate(uint32_t in_len)
    {
        in = (uint8_t *)calloc(1, in_len);
        if (!in) {
            return crypto_error::ALLOC_FAILURE;
        }

        return crypto_error::NO_ERROR;
    }

    void free_buf() {
        if (in) {
            free(in);
        }
    }
};

}

#endif
