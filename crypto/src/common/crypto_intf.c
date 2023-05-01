#include <stdlib.h>
#include <crypto_intf.h>
#include <openssl_crypto_intf.h>
#include <mbedtls_crypto_intf.h>

static crypto_intf_context_t ctx;

int register_crypto_intf(crypto_lib_type_t type, crypto_intf_t *intf)
{
    ctx.intf_list[type].type = type;
    ctx.intf_list[type].intf = intf;

    return 0;
}

typedef int (*init_callbacks)(void);

static init_callbacks init_callbacks_list[] = {
    openssl_crypto_intf_init,
    mbedtls_crypto_intf_init,
};

int init_crypto_intf()
{
    int i;
    int ret;

    for (i = 0; i < sizeof(init_callbacks_list) /
                    sizeof(init_callbacks_list[0]); i ++) {
        ret = init_callbacks_list[i]();
    }

    return ret;
}

int crypto_hash(crypto_hash_in_t *hash_in,
                crypto_hash_out_t *hash_out)
{
    crypto_intf_list_t *cry;

    cry = &ctx.intf_list[hash_in->lib_type];
    crypto_intf_t *cryp_intf = cry->intf;

    if (cryp_intf->hash_intf &&
        cryp_intf->hash_intf->hash) {
        cryp_intf->hash_intf->hash(hash_in, hash_out);
    }

    return 0;
}

