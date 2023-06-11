#ifndef __NOS_PACKET_IPV6_H__
#define __NOS_PACKET_IPV6_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

#define IPV6_VERSION 6

/**
 * @brief - Implements ipv6 header.
*/
struct ipv6_header {
    uint8_t         version;
    uint8_t         traffic_class;
    uint32_t        flow_label;
    uint16_t        payload_len;
    uint8_t         next_header;
    uint8_t         hop_limit;
    uint8_t         source_addr[16];
    uint8_t         dest_addr[16];

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

}

#endif
