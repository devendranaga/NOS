cmake_minimum_required(VERSION 3.8)

project(Firewall)

if(CONFIG_USE_CLANG)
    set(CMAKE_C_COMPILER "/usr/bin/clang")
elseif(CONFIG_USE_GCC)
    set(CMAKE_C_COMPILER "/usr/bin/gcc")
endif()

set(DRV_SRC
    ./src/drivers/driver_generic.c
    ./src/drivers/linux_raw/linux_raw.c)

set(OS_SRC
    ./src/lib/os/os_thread.c
    ./src/lib/os/os.c
    ./src/lib/os/os_signal.c)

set(PROTOCOL_SRC
    ./src/lib/protocols/protocol_generic.c
    ./src/lib/protocols/l2/ethernet.c
    ./src/lib/protocols/l2/arp.c
    ./src/lib/protocols/l2/vlan.c
    ./src/lib/protocols/l2/mpls.c
    ./src/lib/protocols/l2/pppoe.c
    ./src/lib/protocols/l2/ptp.c
    ./src/lib/protocols/l2/srp.c
    ./src/lib/protocols/l2/8021ae.c
    ./src/lib/protocols/l2/8021x.c
    ./src/lib/protocols/l3/ipv4.c
    ./src/lib/protocols/l3/ipv6.c
    ./src/lib/protocols/l2/8021ae.c
    ./src/lib/protocols/l4/icmp.c
    ./src/lib/protocols/l4/icmp6.c
    ./src/lib/protocols/l4/udp.c
    ./src/lib/protocols/l4/tcp.c
    ./src/lib/protocols/app/someip.c
    ./src/lib/protocols/app/dhcp.c
    ./src/lib/protocols/app/ntp_v4.c
    ./src/lib/protocols/app/doip.c
    ./src/lib/protocols/app/dns.c)

set(LIB_SRC
    ./src/lib/fw_pkt.c
    ./src/lib/pcap/pcap_ops.c
    ${PROTOCOL_SRC})

set(DEBUG_SRC
    ./src/debug/debug.c)

set(MAIN_SRC
    ./src/main/firewall.c
    ./src/main/firewall_config.c)

set(EVENT_SRC
    ./src/events/events.c
    ./src/events/event_fmt_binary.c)

set(CONFIG_SRC
    ./src/config/fw_config.c)

set(RULES_SRC
    ./src/rules/fw_rules.c)

set(FILTERS_SRC
    ./src/filters/fw_filter.c)

set(SRC
    ${DRV_SRC}
    ${MAIN_SRC}
    ${OS_SRC}
    ${LIB_SRC}
    ${DEBUG_SRC}
    ${EVENT_SRC}
    ${CONFIG_SRC}
    ${RULES_SRC}
    ${FILTERS_SRC})

set(TOOL_SRC
    ./tools/packet_gen/packet_gen.c
    ./tools/packet_gen/pcap_replay.c
    ./src/lib/pcap/pcap_ops.c
    ./src/drivers/linux_raw/linux_raw.c)

set(EVENT_SERVER_SRC
    ./server/event_server/event_server.c)

set(FW_FLAGS "-DCONFIG_DRIVER_RAW_SOCKET")
set(FW_FLAGS "${FW_FLAGS} -DENABLE_PROTOCOL_PRINTS")

set(CMAKE_C_FLAGS "-Wall -Wno-unused-parameter -Wextra -Werror ${FW_FLAGS} ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow -Wno-deprecated-declarations ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-security ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wnull-dereference -fstack-protector-all ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstack-protector ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --param ssp-buffer-size=4 ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-clash-protection -fPIE ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstack-usage=8192 -fstack-usage ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ggdb ")

include_directories(./src/
                    ./src/drivers/
                    ./src/drivers/linux_raw/
                    ./src/main/
                    ./src/lib/
                    ./src/lib/os/
                    ./src/lib/protocols/
                    ./src/lib/protocols/l2/
                    ./src/lib/protocols/l3/
                    ./src/lib/protocols/l4/
                    ./src/lib/protocols/app/
                    ./src/events/
                    ./src/debug/
                    ./src/config/
                    ./src/rules/
                    ./src/lib/pcap/
                    ./src/filters/
                    ./tools/packet_gen/
                    ./server/event_server/)

add_executable(nos_fwd ${SRC})
target_link_libraries(nos_fwd pthread rt)

add_executable(nos_packet_gen ${TOOL_SRC})
target_link_libraries(nos_packet_gen pthread rt)

add_executable(nos_event_serverd ${EVENT_SERVER_SRC})
target_link_libraries(nos_event_serverd pthread rt)

