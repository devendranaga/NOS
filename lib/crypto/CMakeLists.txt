project(crypto)

cmake_minimum_required(VERSION 3.9)

set(COMMON_SRC
    ./src/common/crypto_intf.c
    ./src/common/crypto_common.c)

set(OPENSSL_SRC
    ./src/openssl/openssl_crypto_intf.c
    ./src/openssl/openssl_hash.c)

set(MBEDTLS_SRC
    ./src/mbedtls/mbedtls_crypto_intf.c
    ./src/mbedtls/mbedtls_hash.c)

set(SRC
    ${COMMON_SRC}
    ${OPENSSL_SRC}
    ${MBEDTLS_SRC})

set(PKI_SRC
    ./pki/src/x509_parser.c)

set(TEST_SRC
    ./tests/crypto_main.c)

set(PKI_TEST_SRC
    ./pki/test/x509_test.c)

include_directories(./src/
                    ./src/common/
                    ./src/openssl/
                    ./src/mbedtls/
                    ./pki/src/
                    ../core/src/)

add_library(auto_crypto ${SRC})
target_link_libraries(auto_crypto ssl crypto mbedcrypto)

add_library(nos_x509 ${PKI_SRC})
target_link_libraries(nos_x509 aos_core)

add_executable(crypto_tests ${TEST_SRC})
target_link_libraries(crypto_tests auto_crypto aos_core)

add_executable(x509_tests ${PKI_TEST_SRC})
target_link_libraries(x509_tests aos_core nos_x509)
