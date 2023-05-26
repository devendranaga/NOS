#include <openssl/evp.h>
#include <crypto_intf_hash.h>

namespace nos::crypto {

class openssl_hash : public hash {
    public:
        explicit openssl_hash() {
            OpenSSL_add_all_algorithms();
        }
        ~openssl_hash() {
            OPENSSL_cleanup();
        }

        crypto_error sha2_256(hash_input_buf &in,
                              hash_output &out);
        crypto_error sha2_256(const std::string &in_file,
                              hash_output &out);
        crypto_error sha2_384(hash_input_buf &in,
                              hash_output &out);
        crypto_error sha2_384(const std::string &in_file,
                              hash_output &out);
        crypto_error sha2_512(hash_input_buf &in,
                              hash_output &out);
        crypto_error sha2_512(const std::string &in_file,
                              hash_output &out);
        crypto_error sha3_256(hash_input_buf &in,
                              hash_output &out);
        crypto_error sha3_256(const std::string &in_file,
                              hash_output &out);
        crypto_error sha3_384(hash_input_buf &in,
                              hash_output &out);
        crypto_error sha3_384(const std::string &in_file,
                              hash_output &out);
        crypto_error sha3_512(hash_input_buf &in,
                              hash_output &out);
        crypto_error sha3_512(const std::string &in_file,
                              hash_output &out);
        crypto_error ripemd160(hash_input_buf &in,
                               hash_output &out);
        crypto_error ripemd160(const std::string &in_file,
                               hash_output &out);
};

}
