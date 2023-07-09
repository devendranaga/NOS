#ifndef __NOS_FIREWALL_PACKET_ICMP_H__
#define __NOS_FIREWALL_PACKET_ICMP_H__

#include <stdint.h>
#include <event_types.h>
#include <packet-buf.h>
#include <packet-ipv4.h>
#include <packet-udp.h>

namespace nos::firewall
{

/*
 * ICMP Types.
 */
#define ICMP_REPLY                          0
#define ICMP_DEST_UNREACHABLE               3
#define ICMP_REDIRECT                       5
#define ICMP_REQ                            8
#define ICMP_ROUTER_ADV                     9
#define ICMP_ROUTER_SOL                     10
#define ICMP_TIME_EXCEED                    11
#define ICMP_PARAMETER_PROB                 12
#define ICMP_TIMESTAMP                      13
#define ICMP_TIMESTAMP_REPLY                14

/*
 * ICMP Codes.
 */
#define ICMP_REPLY_CODE                     0

#define ICMP_DEST_NW_UNREACHABLE            0
#define ICMP_DEST_HOST_UNREACHABLE          1
#define ICMP_DEST_PROTO_UNREACHABLE         2
#define ICMP_DEST_PORT_UNREACHABLE          3
#define ICMP_DEST_FRAG_NEEDED               4
#define ICMP_SOURCE_ROUTE_FAILED            5

#define ICMP_REDIR_FOR_NW                   0
#define ICMP_REDIR_DATAGRAM_FOR_HOST        1
#define ICMP_REDIR_DATAGRAM_FOR_TOS_NW      2
#define ICMP_REDIR_DATAGRAM_FOR_SVC_HOST    3

#define ICMP_TTL_EXCEEDED_IN_TRANSIT        0
#define ICMP_FRAG_REASSMEBLY_TIME_EXCEEDED  1

#define ICMP_PTR_IND_ERR                    0
#define ICMP_MISSING_REQ_OPT                1
#define ICMP_BAD_LEN                        2

struct icmp_ping_request {
    uint16_t id;
    uint16_t seq_no;
};

struct icmp_ping_reply {
    uint16_t id;
    uint16_t seq_no;
};

struct icmp_redirect {
    uint32_t ipaddr;
    ipv4_header ipv4_hdr;
    uint8_t datagram_data[8];

    event_type deserialize(packet_buf &buf);
    void print();
};

struct icmp_time_exceeded {
    uint32_t unused;
    ipv4_header ipv4_hdr;
    uint8_t datagram_data[8];

    event_type deserialize(packet_buf &buf);
    void print();
};

struct icmp_timestamp {
    uint16_t identifier;
    uint16_t seq_no;
    uint32_t origin_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;

    event_type deserialize(packet_buf &buf);
    void print();
};

struct icmp_timestamp_reply {
    uint16_t identifier;
    uint16_t seq_no;
    uint32_t origin_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;

    event_type deserialize(packet_buf &buf);
    void print();
};

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    icmp_ping_request       ping_req;
    icmp_ping_reply         ping_reply;
    icmp_redirect           redir;
    icmp_time_exceeded      time_exc;
    icmp_timestamp          timestamp;
    icmp_timestamp_reply    timestamp_reply;

    uint32_t                remaining_len;

    event_type deserialize(packet_buf &buf);
    void print();
    void free_hdr() { }
};

}

#endif
