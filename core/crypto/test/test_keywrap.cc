#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>

int main()
{
    uint8_t kek[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint8_t key_data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    std::shared_ptr<nos::crypto::keywrap> kw;
    nos::crypto::crypto_symmetric_key key;
    nos::crypto::crypto_symmetric_key tbw_key;
    nos::crypto::crypto_symmetric_key wrap;
    int ret;

    memcpy(key.key, kek, sizeof(kek));
    key.key_len = sizeof(kek);

    memcpy(tbw_key.key, key_data, sizeof(key_data));
    tbw_key.key_len = sizeof(key_data);

    kw = nos::crypto::crypto_factory::instance()->create_keywrap(
                              nos::crypto::crypto_impl::mbedtls);
    ret = kw->wrap(key, tbw_key, wrap);
    if (ret < 0) {
        return -1;
    }

    printf("wrapped key : ");
    for (uint32_t i = 0; i < wrap.key_len; i ++) {
        printf("%02x", wrap.key[i]);
    }
    printf("\n");
    return 0;
}