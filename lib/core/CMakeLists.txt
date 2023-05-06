project(auto_os_c)

cmake_minimum_required(VERSION 3.9)

set(SRC
    ./src/nos_thread.c
    ./src/nos_common.c
    ./src/nos_fileio.c)

include_directories(./src/)

add_library(aos_core ${SRC})
