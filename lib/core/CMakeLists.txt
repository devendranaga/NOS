project(auto_os_c)

cmake_minimum_required(VERSION 3.9)

set(SRC
    ./src/os_thread.c
    ./src/aos_common.c
    ./src/aos_fileio.c)

include_directories(./src/)

add_library(aos_core ${SRC})
