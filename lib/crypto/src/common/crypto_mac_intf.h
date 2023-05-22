#ifndef __AOS_CRYPTO_MAC_INTF_H__
#define __AOS_CRYPTO_MAC_INTF_H__

#include <stdint.h>
#include <crypto_lib_types.h>
#include <crypto_common.h>

typedef enum crypto_mac_type {
    CRYPTO_MAC_TYPE_AES_CMAC_128,
    CRYPTO_MAC_TYPE_AES_CMAC_192,
    CRYPTO_MAC_TYPE_AES_CMAC_256,
    CRYPTO_MAC_TYPE_HMAC_SHA2_256,
    CRYPTO_MAC_TYPE_HMAC_SHA2_384,
    CRYPTO_MAC_TYPE_HMAC_SHA2_512,
    CRYPTO_MAC_TYPE_HMAC_SHA3_256,
    CRYPTO_MAC_TYPE_HMAC_SHA3_384,
    CRYPTO_MAC_TYPE_HMAC_SHA3_512,
    CRYPTO_MAC_TYPE_SIPHASH_24,
    CRYPTO_MAC_TYPE_GMAC_128,
    CRYPTO_MAC_TYPE_GMAC_192,
    CRYPTO_MAC_TYPE_GMAC_256,
} crypto_mac_type_t;

typedef struct crypto_mac_data_in {
    crypto_mac_type_t   mac_type;
    crypto_lib_type_t   lib_type;
    const char          *keyfile;
    const uint8_t       *buf_in;
    uint32_t            buf_size;
    const char          *filename;
} crypto_mac_params_in_t;

typedef struct crypto_mac_data_out {
    uint8_t             data[64];
    uint32_t            data_len;
} crypto_mac_params_out_t;

typedef struct crypto_mac_intf {
    int (*generate)(crypto_mac_params_in_t *mac_data_in,
                    crypto_mac_params_out_t *mac_data_out);
    bool (*verify)(crypto_mac_params_in_t *mac_data_in,
                   crypto_mac_params_out_t *mac_data_out);
} crypto_mac_intf_t;

#endif
