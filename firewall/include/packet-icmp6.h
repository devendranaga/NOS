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
#define ICMP6_ROUTER_ADVERTISEMENT      0x86
#define ICMP6_NEIGHBOR_SOLICITATION     0x87

struct icmp6_ra_flags {
    uint8_t managed_addr_conf:1;
    uint8_t other_conf:1;
    uint8_t home_agent:1;
    uint8_t prf:2;
    uint8_t proxy:1;
    uint8_t reserved:1;
} __attribute__ ((__packed__));

struct icmp6_option_prefix_info_flags {
    uint8_t onlink:1;
    uint8_t auto_addr_conf:1;
    uint8_t router_addr:1;
    uint8_t reserved:5;
} __attribute__ ((__packed__));

struct icmp6_option_prefix_info {
    uint8_t type;
    uint8_t length;
    uint8_t prefix_length;
    icmp6_option_prefix_info_flags flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint32_t reserved;
    uint8_t prefix[16];
};

struct icmp6_router_advertisement {
#define ICMP6_RA_OPT_TYPE_PREFIX_INFO   3
#define ICMP6_RA_OPT_TYPE_RECURSIVE_DNS 25
    uint8_t cur_hoplimit;
    icmp6_ra_flags ra_flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
    icmp6_option_prefix_info prefix_info;
};

struct icmp6_option_source_link_layer {
#define ICMP6_OPT_SOURCE_LINK_LAYER 1
    uint8_t type;
    uint8_t len;
    uint8_t link_layer_addr[6];

    event_type deserialize(packet_buf &buf);
};

struct icmp6_neighbor_solicitation {
    uint32_t reserved;
    uint8_t target_addr[16];
    icmp6_option_source_link_layer source_link_layer;
};

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
    icmp6_router_advertisement ra;
    icmp6_neighbor_solicitation ns;

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

}

#endif
