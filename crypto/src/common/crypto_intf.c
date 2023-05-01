#include <stdlib.h>
#include <crypto_intf.h>
#include <openssl_crypto_intf.h>

static crypto_intf_context_t ctx;

int register_crypto_intf(crypto_lib_type_t type, crypto_intf_t *intf)
{
    crypto_intf_list_t *item;

    item = calloc(1, sizeof(crypto_intf_list_t));
    if (!item) {
        return -1;
    }

    item->type = type;
    item->intf = intf;

    if (!ctx.intf_h) {
        ctx.intf_h = item;
        ctx.intf_t = item;
    } else {
        ctx.intf_t->next = item;
        ctx.intf_t = item;
    }

    return 0;
}

int init_crypto_intf()
{
    int ret;

    ret = openssl_crypto_intf_init();
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int crypto_hash(crypto_hash_in_t *hash_in,
                crypto_hash_out_t *hash_out)
{
    crypto_intf_list_t *cry;

    for (cry = ctx.intf_h; cry != NULL; cry = cry->next) {

        if ((cry->type == CRYPTO_LIB_OPENSSL) && cry->intf) {
            crypto_intf_t *cryp_intf = cry->intf;

            if (cryp_intf->hash_intf &&
                cryp_intf->hash_intf->hash) {
                cryp_intf->hash_intf->hash(hash_in, hash_out);
            }
        }
    }

    return 0;
}

