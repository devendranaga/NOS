cmake_minimum_required(VERSION 3.8)

project(packet_gen)

set(SRC
    ./packet_gen.cc)

include_directories(./
                    ../../core/include/)

add_executable(nos_packet_gen ${SRC})
target_link_libraries(nos_packet_gen nos_core)
