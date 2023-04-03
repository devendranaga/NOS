/**
 * @brief - Implements IPv4 Header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_IPV4_H__
#define __LIB_PROTOCOLS_IPV4_H__

#define FW_IPV4_PROTOCOL_ICMP 1

struct ipv4_header {
    uint8_t version;
    uint8_t header_len;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_len;
    uint16_t identification;
    bool reserved;
    bool dont_fragment;
    bool more_fragment;
    uint32_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_chksum;
    uint32_t src_ipaddr;
    uint32_t dst_ipaddr;
};

typedef struct ipv4_header ipv4_header_t;

bool ipv4_pkt_has_fragments(ipv4_header_t *hdr);

#endif

