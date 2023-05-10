project(auto_os_c)

cmake_minimum_required(VERSION 3.9)

set(SRC
    ./src/nos_thread.c
    ./src/nos_common.c
    ./src/nos_fileio.c
    ./src/config_parser/nos_config_parser.c
    ./src/nos_logger.c
    ./src/nos_socket.c)

set(TEST_SRC
    ./tests/test_config_parser.c)

set(TEST_NOS_LOGGER_SRC
    ./tests/test_nos_logger.c)

include_directories(./src/
                    ./src/config_parser/)

set(CMAKE_C_FLAGS "-Wall -g -ggdb")

add_library(aos_core ${SRC})

add_executable(test_config_parser ${TEST_SRC})
add_executable(test_nos_logger ${TEST_NOS_LOGGER_SRC})

target_link_libraries(test_config_parser aos_core)
target_link_libraries(test_nos_logger aos_core)
