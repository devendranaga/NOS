project(crypto)

cmake_minimum_required(VERSION 3.9)

set(CORE_SRC
    ./src/core/crypto_factory.cc)

set(OPENSSL_SRC
    ./src/openssl/openssl_intf_hash.cc)

set(TEST_SRC
    ./src/tests/test_main.cc
    ./src/tests/test_hash_functions.cc)

set(SRC
    ${CORE_SRC}
    ${OPENSSL_SRC})

set(PKI_SRC
    ./pki/src/x509_parser.c)

set(PKI_TEST_SRC
    ./pki/test/x509_test.c)

include_directories(./src/
                    ./src/core/
                    ./src/core/interface/
                    ./src/tests/
                    ./src/openssl/
                    ./src/mbedtls/
                    ./pki/src/
                    ../core/src/)

add_library(nos_crypto ${SRC})
target_link_libraries(nos_crypto ssl crypto mbedcrypto)

add_library(nos_x509 ${PKI_SRC})
target_link_libraries(nos_x509 aos_core)

add_executable(x509_tests ${PKI_TEST_SRC})
target_link_libraries(x509_tests aos_core nos_x509)

add_executable(crypto_tests ${TEST_SRC})
target_link_libraries(crypto_tests nos_crypto)
