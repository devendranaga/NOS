project(crypto)

cmake_minimum_required(VERSION 3.9)

set(SRC
    ./src/nos_log_service.cc)

include_directories(./src/
                    ../../lib/core/src/
                    ../core/src/)

add_executable(nos_loggerd ${SRC})
target_link_libraries(nos_loggerd aos_core pthread)
