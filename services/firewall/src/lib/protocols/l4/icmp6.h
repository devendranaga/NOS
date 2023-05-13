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
#define ICMP6_TYPE_ROUTER_ADVERTISEMENT     0x86
#define ICMP6_TYPE_ROUTER_SOLICITATION      0x85

typedef struct icmp6_ping_req_hdr {
    uint16_t                        id;
    uint16_t                        seq;
} icmp6_ping_req_hdr_t;

#define ICMP6_OPT_TYPE_SOURCE_LLADDR        1
#define ICMP6_OPT_TYPE_PREFIX_INFO          3
#define ICMP6_OPT_TYPE_MTU                  5
#define ICMP6_OPT_TYPE_NONCE                14

typedef struct icmp6_options {
    uint8_t                         type;
    uint8_t                         len;
    uint8_t                         nonce[8];
} icmp6_options_t;

typedef enum icmp6_options_flags {
    ICMP6_OPT_FLAGS_SOURCE_LLADDR   = 0x0001,
    ICMP6_OPT_FLAGS_PREFIX_INFO     = 0x0002,
    ICMP6_OPT_FLAGS_MTU             = 0x0004,
    ICMP6_OPT_FLAGS_NONCE           = 0x0008,
} icmp6_options_flags_t;

typedef struct icmp6_options_source_ll {
    uint8_t                         type;
    uint8_t                         len;
    uint8_t                         lladdr[6];
} icmp6_options_source_ll_t;

typedef struct icmp6_options_mtu {
    uint8_t                         type;
    uint8_t                         len;
    uint16_t                        reserved;
    uint32_t                        mtu;
} icmp6_options_mtu_t;

typedef struct icmp6_options_prefix_info {
    uint8_t                         type;
    uint8_t                         len;
    uint8_t                         prefix_len;
    uint8_t                         flags_onlink;
    uint8_t                         flags_autonomous_addr;
    uint8_t                         flags_router_addr;
    uint32_t                        valid_lifetime;
    uint32_t                        preferred_lifetime;
    uint32_t                        reserved;
    uint8_t                         prefix[16];
} icmp6_options_prefix_info_t;

typedef struct icmp6_neighbor_solicitation {
    uint32_t                        reserved;
    uint8_t                         target_addr[16];
    icmp6_options_t                 opt;
} icmp6_neighbor_solicitation_t;

typedef struct icmp6_router_solicitation {
    uint32_t                        reserved;
} icmp6_router_solicitation_t;

typedef struct icmp6_router_advertisement {
    uint8_t                         cur_hop_limit;
    uint8_t                         flags_managed_addr_config;
    uint8_t                         flags_other_config;
    uint8_t                         flags_home_agent;
    uint8_t                         flags_prf;
    uint8_t                         flags_proxy;
    uint8_t                         flags_reserved;
    uint16_t                        router_lifetime;
    uint32_t                        reachable_time;
    uint32_t                        retransmission_timer;
    icmp6_options_flags_t           opt_flags;
    icmp6_options_source_ll_t       opt_source_ll;
    icmp6_options_mtu_t             opt_mtu;
    icmp6_options_prefix_info_t     opt_prefix_info;
} icmp6_router_advertisement_t;

typedef struct icmp6_header {
    uint8_t                         type;
    uint8_t                         code;
    uint16_t                        checksum;
    icmp6_ping_req_hdr_t            ping_req;
    icmp6_ping_req_hdr_t            ping_reply;
    icmp6_neighbor_solicitation_t   ns;
    icmp6_router_solicitation_t     rs;
    icmp6_router_advertisement_t    ra;
} icmp6_header_t;

#endif
