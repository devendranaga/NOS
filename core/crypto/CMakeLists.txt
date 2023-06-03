cmake_minimum_required(VERSION 3.8)

project(crypto)

set(MBEDTLS_SRC
    ./mbedtls/mbedtls_keywraps.cc)

set(COMMON_SRC
    ./common/crypto_factory.cc)

set(SRC
    ${MBEDTLS_SRC}
    ${COMMON_SRC})

set(TEST_SRC
    ./test/test_keywrap.cc)

set(MBEDTLS_INCL
    ./mbedtls)

include_directories(./
                    ./common/
                    ./include/
                    ${MBEDTLS_INCL})

add_library(nos_crypto ${SRC})
target_link_libraries(nos_crypto mbedcrypto mbedtls)

add_executable(nos_crypto_test ${TEST_SRC})
target_link_libraries(nos_crypto_test mbedcrypto mbedtls nos_crypto)

