/**
 * @brief Implements interface to HKDF function.
 *
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
*/
#ifndef __NOS_CRYPTO_INTF_HKDF_H__
#define __NOS_CRYPTO_INTF_HKDF_H__

#include <cstring>
#include <stdint.h>
#include <string>
#include <crypto_error.h>
#include <crypto_intf_buf.h>

namespace nos::crypto {

struct hkdf_params {
    crypto_buf salt;
    crypto_buf device_id;

    explicit hkdf_params(const crypto_buf &salt_in, const crypto_buf &device_id_in) :
                    salt(salt_in), device_id(device_id_in) { }
    ~hkdf_params() { }
};

class hkdf {
    public:
        explicit hkdf() = default;
        ~hkdf() = default;

        virtual int derive_key(const std::string &in_key,
                               const hkdf_params &params,
                               const std::string &out_key) = 0;
};

}

#endif
