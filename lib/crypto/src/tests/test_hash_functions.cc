#include <cstdint>
#include <iostream>
#include <string>
#include <memory>
#include <crypto_intf_hash.h>
#include <crypto_factory.h>

namespace nos::crypto::tests {

struct hash_test_vectors {
    std::string hash_name;
    uint8_t in_data[256];
    uint32_t msg_len;
    uint8_t hash[32];
    uint32_t hash_len;
} test_vectors[] = {
    {"SHA256", {0}, 0,
     {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
     },
     32
    },
    {"SHA256", {'a', 'b', 'c'}, 3,
     {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
      0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
      0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
     },
     32
    }
};

int test_hash_functions(const nos::crypto::crypto_support &support)
{
    std::unique_ptr<hash> hash_impl;
    uint32_t i;
    crypto_error err;

    hash_impl = nos::crypto::crypto_factory::get_hash_intf(support);

    for (i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]); i ++) {
        if (test_vectors[i].hash_name == "SHA256") {
            hash_input_buf in_buf(test_vectors[i].in_data, test_vectors[i].msg_len);
            hash_output out;

            err = hash_impl->sha2_256(in_buf, out);
            if (err != crypto_error::NO_ERROR) {
                printf("%s : [%d] fail\n", test_vectors[i].hash_name.c_str(), i);
                return -1;
            }
            if (std::memcmp(out.hash, test_vectors[i].hash, test_vectors[i].hash_len) != 0) {
                printf("%s : [%d] fail\n", test_vectors[i].hash_name.c_str(), i);
                return -1;
            }

            printf("%s : [%d] pass\n", test_vectors[i].hash_name.c_str(), i);
        }
    }

    return 0;
}

}
