cmake_minimum_required(VERSION 3.8)

project(core)

set(SRC
    ./src/evt_mgr_intf.cc
    ./src/raw_socket.cc
    ./src/file_intf.cc
    ./src/time_intf.cc 
    ./src/nos_logging_console.cc
    ./src/udp_socket_intf.cc
    ./src/nos_logging_file.cc)

include_directories(./src/
                    ./include/)

set(TEST_SRC
    ./test/test_logger.cc
    ./test/test_main.cc)

add_library(nos_core ${SRC})

add_executable(nos_core_test ${TEST_SRC})
target_link_libraries(nos_core_test nos_core pthread)

add_subdirectory(crypto)
