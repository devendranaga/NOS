#ifndef __NOS_FIREWALL_PACKET_ICMP_H__
#define __NOS_FIREWALL_PACKET_ICMP_H__

#include <stdint.h>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

#define PING_REQ 0x08
#define PING_REPLY 0x00

struct icmp_ping_request {
    uint16_t id;
    uint16_t seq_no;
};

struct icmp_ping_reply {
    uint16_t id;
    uint16_t seq_no;
};

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    icmp_ping_request ping_req;
    icmp_ping_reply ping_reply;

    event_type deserialize(packet_buf &buf);
    void print();
    void free_hdr() { }
};

}

#endif
