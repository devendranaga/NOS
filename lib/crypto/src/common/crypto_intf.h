#ifndef __CRYPTO_INTF_H__
#define __CRYPTO_INTF_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <crypto_lib_types.h>
#include <crypto_common.h>
#include <crypto_hash_intf.h>
#include <crypto_mac_intf.h>
#include <crypto_aes_intf.h>

typedef struct crypto_intf {
    crypto_hash_intf_t      *hash_intf;
    crypto_mac_intf_t       *mac_intf;
    crypto_aes_intf_t       *aes_intf;
} crypto_intf_t;

typedef struct crypto_intf_list {
    crypto_lib_type_t       type;
    crypto_intf_t           *intf;
} crypto_intf_list_t;

typedef struct crypto_intf_context {
    crypto_intf_list_t intf_list[3];
} crypto_intf_context_t;

int init_crypto_intf();
int register_crypto_intf(crypto_lib_type_t type, crypto_intf_t *intf);

#endif
