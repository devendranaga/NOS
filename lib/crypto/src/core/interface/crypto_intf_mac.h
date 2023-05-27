/**
 * @brief Implements interface to MAC functions.
 *
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
*/
#ifndef __NOS_CRYPTO_INTF_MAC_H__
#define __NOS_CRYPTO_INTF_MAC_H__

#include <cstring>
#include <stdint.h>
#include <string>
#include <crypto_error.h>
#include <crypto_intf_buf.h>

namespace nos::crypto {

enum mac_type {
    HMAC_SHA2_256,
    HMAC_SHA2_384,
    HMAC_SHA2_512,
    AES_128_CMAC,
    AES_192_CMAC,
    AES_256_CMAC,
    AES_128_GMAC,
    AES_192_GMAC,
    AES_256_GMAC,
    SIPHASH_24,
};

struct mac_params {
    crypto_buf in_buf;
    mac_type mac;
};

struct mac_data {
    crypto_buf mac;
    /* In case of GMAC. */
    crypto_buf iv_out;
};

class mac {
    public:
        explicit mac() = default;
        ~mac() = default;

        virtual crypto_error generate(const std::string &in_key,
                                      const mac_params &in_params,
                                      mac_data &out_data) = 0;
        virtual crypto_error verify(const std::string &in_key,
                                    const mac_params &in_params,
                                    const mac_data &in_mac) = 0;
};

}

#endif
