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

struct icmp6_ping_req_hdr {
    uint16_t id;
    uint16_t seq;
};

typedef struct icmp6_ping_req_hdr icmp6_ping_req_hdr_t;

struct icmp6_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    icmp6_ping_req_hdr_t ping_req;
    icmp6_ping_req_hdr_t ping_reply;
};

typedef struct icmp6_header icmp6_header_t;

#endif
