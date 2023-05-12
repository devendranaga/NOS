/**
 * @brief - Implements IPv4 Header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_ICMP6_H__
#define __LIB_PROTOCOLS_ICMP6_H__

#include <stdint.h>

#define ICMP6_TYPE_ECHO_REQUEST             0x80
#define ICMP6_TYPE_ECHO_REPLY               0x81
#define ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT   0x88
#define ICMP6_TYPE_NEIGHBOR_SOLICITATION    0x87
#define ICMP6_TYPE_ROUTER_SOLICITATION      0x85

typedef struct icmp6_ping_req_hdr {
    uint16_t id;
    uint16_t seq;
} icmp6_ping_req_hdr_t;

#define ICMP6_OPT_TYPE_NONCE 14

typedef struct icmp6_options {
    uint8_t type;
    uint8_t len;
    uint8_t nonce[8];
} icmp6_options_t;

typedef struct icmp6_neighbor_solicitation {
    uint32_t reserved;
    uint8_t target_addr[16];
    icmp6_options_t opt;
} icmp6_neighbor_solicitation_t;

typedef struct icmp6_router_solicitation {
    uint32_t reserved;
} icmp6_router_solicitation_t;

typedef struct icmp6_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    icmp6_ping_req_hdr_t ping_req;
    icmp6_ping_req_hdr_t ping_reply;
    icmp6_neighbor_solicitation_t ns;
    icmp6_router_solicitation_t rs;
} icmp6_header_t;

#endif
