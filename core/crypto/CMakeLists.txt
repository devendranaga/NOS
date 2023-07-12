cmake_minimum_required(VERSION 3.8)

project(crypto)

set(MBEDTLS_SRC
    ./mbedtls/mbedtls_keywraps.cc
    ./mbedtls/mbedtls_hmac.cc
    ./mbedtls/mbedtls_hkdf.cc
    ./mbedtls/mbedtls_hash.cc
    ./mbedtls/mbedtls_crypto_random.cc
    ./mbedtls/mbedtls_aes_cmac.cc
    ./mbedtls/mbedtls_aes_cbc.cc
    ./mbedtls/mbedtls_aes_xts.cc)

set(OPENSSL_SRC
    ./openssl/openssl_hash.cc
    ./openssl/openssl_hmac.cc
    ./openssl/openssl_cmac.cc
    ./openssl/openssl_random.cc
    ./openssl/openssl_aes_cbc.cc)

set(COMMON_SRC
    ./common/crypto_factory.cc)

set(SRC
    ${MBEDTLS_SRC}
    ${OPENSSL_SRC}
    ${COMMON_SRC})

set(CMAKE_CXX_FLAGS "-Wall -g -DOPENSSL_API_COMPAT=0x10100000L")

set(TEST_SRC
    ./test/test_keywrap.cc
    ./test/test_hmac.cc
    ./test/test_hkdf.cc
    ./test/test_hash.cc
    ./test/test_aes_cmac.cc
    ./test/test_aes_cbc.cc
    ./test/test_main.cc)

set(MBEDTLS_INCL
    ./mbedtls)

set(OPENSSL_INCL
    ./openssl)

include_directories(./
                    ./common/
                    ./include/
                    ${MBEDTLS_INCL}
                    ${OPENSSL_INCL})

add_library(nos_crypto ${SRC})
target_link_libraries(nos_crypto mbedcrypto mbedtls ssl crypto nos_core)

add_executable(nos_crypto_test ${TEST_SRC})
target_link_libraries(nos_crypto_test mbedcrypto mbedtls nos_crypto nos_core)

