#ifndef __NOS_PACKET_IPV4_H__
#define __NOS_PACKET_IPV4_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

#define IPV4_VERSION 4
#define IPV4_IHL_LEN_MIN 5
#define IPV4_IHL_LEN_MAX 15

/**
 * @brief - Implements ipv4 header.
 */
struct ipv4_header {
    uint8_t         version;
    uint8_t         ihl;
    uint8_t         dscp;
    uint8_t         ecn;
    uint16_t        total_len;
    uint16_t        id;
    uint8_t         flags_reserved:1;
    uint8_t         flags_dont_fragment:1;
    uint8_t         flags_more_fragment:1;
    uint16_t        frag_off;
    uint8_t         ttl;
    uint8_t         protocol;
    uint16_t        hdr_chksum;
    uint32_t        source_ipaddr;
    uint32_t        dest_ipaddr;
    bool            header_parsed_ok;

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }

    inline bool has_fragment()
    { return (flags_more_fragment == 1) || (frag_off != 0); }

    inline bool ipv4_has_options()
    { return (ihl > IPV4_IHL_LEN_MAX); }
};

}

#endif
