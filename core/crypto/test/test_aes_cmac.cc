#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>

int test_aes_cmac()
{
    uint8_t data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    };
    uint8_t key[] = {
        0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
        0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
    };
    std::shared_ptr<nos::crypto::aes_cmac> cmac;
    nos::crypto::crypto_symmetric_key key_1(key, sizeof(key));
    nos::crypto::crypto_mac_buffer mac;
    int ret;

    cmac = nos::crypto::crypto_factory::instance()->create_aes_cmac(
                            nos::crypto::crypto_impl::mbedtls);
    ret = cmac->sign_128(data, sizeof(data), key_1, mac);
    if (ret < 0) {
        return -1;
    }

    printf("AES-128-CMAC: ");
    for (uint32_t i = 0; i < mac.signature_len; i ++) {
        printf("%02x", mac.signature[i]);
    }
    printf("\n");

    ret = cmac->verify_128(data, sizeof(data), key_1, mac);
    if (ret < 0) {
        printf("AES-128-CMAC: verify failed\n");
        return -1;
    }

    printf("AES-128-CMAC: verify ok\n");

    return 0;
}