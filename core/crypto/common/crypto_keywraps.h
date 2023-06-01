#ifndef __NOS_CRYPTO_KEYWRAPS_H__
#define __NOS_CRYPTO_KEYWRAPS_H__

#include <string>
#include <crypto_buffers.h>

namespace nos::crypto {

class keywrap {
    public:
        explicit keywrap() = default;
        ~keywrap() = default;

        virtual int wrap(const std::string &kek,
                         const std::string &tbw_key,
                         const std::string &wrapped_key) = 0;
        virtual int unwrap(const std::string &kek,
                           const std::string &wrapped_key,
                           const std::string &unwrapped_key) = 0;
        virtual int wrap(const crypto_symmetric_key &kek,
                         crypto_symmetric_key &tbw_key,
                         crypto_symmetric_key &wrapped_key) = 0;
        virtual int unwrap(const crypto_symmetric_key &kek,
                           crypto_symmetric_key &wrapped_key,
                           crypto_symmetric_key &unwrapped_key) = 0;
};

}

#endif
