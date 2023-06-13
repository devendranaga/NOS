/**
 * @brief - implements ICMP6 packet header.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_PACKET_ICMP6_H__
#define __NOS_PACKET_ICMP6_H__

#include <stdint.h>
#include <string.h>
#include <vector>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

#define ICMP6_ECHO_REQUEST              0x80
#define ICMP6_ECHO_REPLY                0x81
#define ICMP6_MCAST_LISTENER_REPORT_V2  0x8f

struct icmp6_multicast_address {
    uint8_t rec_type;
    uint8_t aux_data;
    uint16_t n_sources;
    uint8_t mcast_addr[16];

    event_type deserialize(packet_buf &buf);
};

struct icmp6_multicast_listener_report {
    uint16_t n_reports;
    std::vector<icmp6_multicast_address> addr_list;
};

struct icmp6_echo_request {
    uint16_t identifier;
    uint16_t sequence;
    uint16_t data_len;
};

struct icmp6_echo_reply {
    uint16_t identifier;
    uint16_t sequence;
    uint16_t data_len;
};

struct icmp6_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    icmp6_echo_request echo_req;
    icmp6_echo_reply echo_rep;
    icmp6_multicast_listener_report mcast_listener;

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

}

#endif
