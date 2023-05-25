#ifndef __NOS_CRYPTO_SUPPORT_H__
#define __NOS_CRYPTO_SUPPORT_H__

namespace nos::crypto {

enum crypto_support {
    OpenSSL,
    WolfSSL,
    MbedTLS,
};

}

#endif
