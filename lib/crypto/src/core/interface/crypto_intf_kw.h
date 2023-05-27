/**
 * @brief Implements interface to Key Wrap functions.
 *
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
*/
#ifndef __NOS_CRYPTO_INTF_KEYWRAP_H__
#define __NOS_CRYPTO_INTF_KEYWRAP_H__

#include <cstring>
#include <stdint.h>
#include <string>
#include <crypto_error.h>

namespace nos::crypto {

class key_wrap {
    public:
        explicit key_wrap() { }
        ~key_wrap() { }

        int wrap(const std::string &in_key,
                 const std::string &wraped_key);
        int unwrap(const std::string &wrapped_key,
                   const std::string &unwrapped_key);
};

}

#endif
