cmake_minimum_required(VERSION 3.8)

project(firewall)

set(SRC
    ./src/firewall.cc)

include_directories(./src/
                    ./include/)

add_executable(nos_firewall ${SRC})
target_link_libraries(nos_firewall nos_core pthread)
