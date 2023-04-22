#ifndef __LIB_PROTOCOLS_IPV6_H__
#define __LIB_PROTOCOLS_IPV6_H__

#include <stdint.h>

#define IPV6_ADDR_LEN 16

struct ipv6_header {
    uint8_t version;
    uint8_t tc;
    uint8_t dscp;
    uint8_t ecn;
    uint32_t flow_label;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hoplimit;
    uint8_t src_ip6addr[IPV6_ADDR_LEN];
    uint8_t dst_ip6addr[IPV6_ADDR_LEN];
};

typedef struct ipv6_header ipv6_header_t;

#endif
