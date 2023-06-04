cmake_minimum_required(VERSION 3.8)

project(firewall)

set(SRC
    ./src/firewall.cc
    ./src/firewall-parser.cc
    ./src/firewall-event.cc
    ./src/packet.cc
    ./src/packet-eth.cc
    ./src/packet-arp.cc
    ./src/packet-ipv4.cc
    ./src/firewall_event_mgr.cc)

include_directories(./src/
                    ./include/
                    ../core/include/)

add_executable(nos_firewall ${SRC})
target_link_libraries(nos_firewall nos_core pthread jsoncpp)
