#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>

int test_hkdf()
{
    uint8_t kek[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint8_t data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    std::shared_ptr<nos::crypto::hkdf_intf> hkdf;
    nos::crypto::crypto_symmetric_key ikm;
    nos::crypto::crypto_symmetric_key okm;
    nos::crypto::crypto_context_buffer salt;
    nos::crypto::crypto_context_buffer ctx;
    nos::crypto::crypto_mac_buffer mac;
    int ret;

    memcpy(ikm.key, kek, sizeof(kek));
    ikm.key_len = sizeof(kek);

    okm.key_len = 64;

    hkdf = nos::crypto::crypto_factory::instance()->create_hkdf(
                              nos::crypto::crypto_impl::mbedtls);
    ret = hkdf->hkdf_hmac_sha256(&salt, &ikm, &ctx, &okm);
    if (ret < 0) {
        return -1;
    }

    printf("hkdf-hmac-sha256 : ");
    for (uint32_t i = 0; i < okm.key_len; i ++) {
        printf("%02x", okm.key[i]);
    }
    printf("\n");

    return 0;
}