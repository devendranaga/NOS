#ifndef __AOS_OPENSSL_CRYPTO_COMMON_H__
#define __AOS_OPENSSL_CRYPTO_COMMON_H__

#define LIBACORE_OPENSSL_RET_CHECK(__res) { \
    if (__res != 1) { \
        return -1; \
    } \
}

#endif

