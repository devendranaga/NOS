#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>
#include <nos_core.h>

int test_aes_cbc(nos::crypto::crypto_impl impl)
{
    uint8_t kek[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint8_t data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    std::shared_ptr<nos::crypto::aes_cbc> cbc_mode;
    nos::crypto::crypto_symmetric_key key_1(kek, sizeof(kek));
    nos::crypto::crypto_iv iv_data;
    uint8_t enc[64] = {0};
    uint32_t enc_len = 0;
    uint8_t dec[64] = {0};
    uint32_t dec_len = 0;
    int ret;

    cbc_mode = nos::crypto::crypto_factory::instance()->create_aes_cbc(impl);
    ret = cbc_mode->encrypt_128(key_1, data, sizeof(data), iv_data, enc);
    if (ret < 0) {
        return -1;
    }

    enc_len = ret;

    nos::core::hexdump("AES-128-CBC: [enc] ", enc, enc_len);

    ret = cbc_mode->decrypt_128(key_1, enc, enc_len, iv_data, dec);
    if (ret < 0) {
        return -1;
    }

    dec_len = ret;

    nos::core::hexdump("AES-128-CBC: [dec] ", dec, dec_len);
    return 0;
}
