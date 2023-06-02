cmake_minimum_required(VERSION 3.8)

project(core)

set(SRC
    ./src/evt_mgr.cc
    ./src/raw_socket.cc
    ./src/file_intf.cc
    ./src/time_intf.cc)

include_directories(./src/
                    ./include/)

add_library(nos_core ${SRC})
add_subdirectory(crypto)
