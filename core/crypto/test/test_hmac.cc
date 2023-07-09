#include <iostream>
#include <string.h>
#include <memory>
#include <crypto_factory.h>
#include <nos_log_factory.h>

int test_hmac(nos::crypto::crypto_impl impl)
{
    uint8_t kek[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint8_t data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    };
    std::shared_ptr<nos::crypto::hmac_intf> hmac;
    nos::crypto::crypto_symmetric_key key;
    nos::crypto::crypto_mac_buffer mac;
    int ret;

    memcpy(key.key, kek, sizeof(kek));
    key.key_len = sizeof(kek);
    hmac = nos::crypto::crypto_factory::instance()->create_hmac(impl);
    ret = hmac->generate(nos::crypto::hash_function_types::SHA2_256,
                         key, data, sizeof(data),
                         mac);
    if (ret < 0) {
        printf("failed to hmac with [%d]\n", impl);
        return -1;
    }

    printf("hmac-sha256 [%d] : ", impl);
    for (uint32_t i = 0; i < mac.signature_len; i ++) {
        printf("%02x", mac.signature[i]);
    }
    printf("\n");

    ret = hmac->verify(nos::crypto::hash_function_types::SHA2_256,
                       key, data, sizeof(data),
                       mac);
    printf("hmac-sha256 verify : %s\n", (ret == 0) ? "Ok" : "Not Ok");

    return 0;
}