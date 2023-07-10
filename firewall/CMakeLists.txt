cmake_minimum_required(VERSION 3.8)

project(firewall)

set(SRC
    ./src/firewall.cc
    ./src/firewall-parser.cc
    ./src/firewall-event.cc
    ./src/packet.cc
    ./src/packet-eth.cc
    ./src/packet-arp.cc
    ./src/packet-ieee8021ae.cc
    ./src/packet-ieee8021x.cc
    ./src/packet-ipv4.cc
    ./src/packet-ipv6.cc
    ./src/packet-icmp.cc
    ./src/packet-icmp6.cc
    ./src/packet-udp.cc
    ./src/packet-tcp.cc
    ./src/packet-doip.cc
    ./src/packet-mqtt.cc
    ./src/packet-ntp.cc
    ./src/firewall_event_mgr.cc
    ./src/firewall-rules.cc
    ./src/firewall-filter.cc
    ./src/firewall-eth-filter.cc)

include_directories(./src/
                    ./include/
                    ../core/include/)

add_executable(nos_firewall ${SRC})
target_link_libraries(nos_firewall nos_core pthread jsoncpp)
