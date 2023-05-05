#ifndef __AOS_CRYPTO_AES_INTF_H__
#define __AOS_CRYPTO_AES_INTF_H__

#include <stdint.h>
#include <crypto_lib_types.h>

typedef enum crypto_aes_mode {
    /* AES-CBC */
    CRYPTO_AES_MODE_CBC_128,
    CRYPTO_AES_MODE_CBC_192,
    CRYPTO_AES_MODE_CBC_256,
    /* AES-GCM */
    CRYPTO_AES_MODE_GCM_128,
    CRYPTO_AES_MODE_GCM_192,
    CRYPTO_AES_MODE_GCM_256,
    /* AES-CCM */
    CRYPTO_AES_MODE_CCM_128,
    CRYPTO_AES_MODE_CCM_192,
    CRYPTO_AES_MODE_CCM_256,
    /* AES-OFB */
    CRYPTO_AES_MODE_OFB_128,
    CRYPTO_AES_MODE_OFB_192,
    CRYPTO_AES_MODE_OFB_256,
    /* AES-XTS */
    CRYPTO_AES_MODE_XTS_128,
    CRYPTO_AES_MODE_XTS_192,
    CRYPTO_AES_MODE_XTS_256,
    /* AES-CTR */
    CRYPTO_AES_MODE_CTR_128,
    CRYPTO_AES_MODE_CTR_192,
    CRYPTO_AES_MODE_CTR_256,
    /* AES-CFB */
    CRYPTO_AES_MODE_CFB_128,
    CRYPTO_AES_MODE_CFB_192,
    CRYPTO_AES_MODE_CFB_256,
} crypto_aes_mode_t;

typedef struct crypto_aes_data_enc_in {
    crypto_aes_mode_t   aes_mode;
    crypto_lib_type_t   lib_type;
    const char          *keyfile;
    uint8_t             *plain_text;
    uint32_t            plain_text_len;
    const char          *filename;
} crypto_aes_plain_text_params_t;

typedef struct crypto_aes_data_enc_out {
    crypto_aes_mode_t   aes_mode;
    crypto_lib_type_t   lib_type;
    uint8_t             *iv;
    uint32_t            iv_len;
    uint8_t             *tag;
    uint32_t            tag_len;
    uint8_t             *cipher_text;
    uint32_t            cipher_text_len;
    const char          *filename;
} crypto_aes_cipher_text_params_t;

typedef struct crypto_aes_intf {
    int (*encrypt)(crypto_aes_plain_text_params_t *aes_plain_text_in,
                   crypto_aes_cipher_text_params_t *aes_cipher_text_out);

    int (*decrypt)(crypto_aes_cipher_text_params_t *aes_cipher_text_in,
                   crypto_aes_plain_text_params_t *aes_plain_text_out);
} crypto_aes_intf_t;

#endif

