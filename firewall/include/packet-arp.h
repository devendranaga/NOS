#ifndef __NOS_PACKET_ARP_H__
#define __NOS_PACKET_ARP_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

#define ARP_OP_ARP_REQ          1
#define ARP_OP_ARP_REPLY        2
#define ARP_OP_RARP_REQ         3
#define ARP_OP_RARP_REPLY       4
#define ARP_OP_DRARP_REQ        5
#define ARP_OP_DRARP_REPLY      6
#define ARP_OP_DRARP_ERROR      7
#define ARP_OP_INARP_REQ        8
#define ARP_OP_INARP_REPLY      9

#define ARP_HEADER_LEN          28

/**
 * @brief - Implements ARP header.
 */
struct arp_header {
    uint16_t        header_type;
    uint16_t        protocol_type;
    uint8_t         hwaddr_len;
    uint8_t         protoaddr_len;
    uint16_t        operation;
    uint8_t         sender_hwaddr[MACADDR_LEN];
    uint32_t        sender_proto_addr;
    uint8_t         target_hwaddr[MACADDR_LEN];
    uint32_t        target_proto_addr;

    inline bool is_arp_req() { return operation == ARP_OP_ARP_REQ; }
    inline bool is_arp_reply() { return operation == ARP_OP_ARP_REPLY; }
    inline bool is_proto_ipv4() { return protocol_type == UNSUPPORTED_ETHERTYPE; }

    event_type deserialize(packet_buf &buf);
    void print();
    void free_hdr() { }
};

}

#endif

