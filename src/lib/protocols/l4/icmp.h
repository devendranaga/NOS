#ifndef __LIB_PROTOCOLS_ICMP_H__
#define __LIB_PROTOCOLS_ICMP_H__

#define ICMP_ECHO_REQ   8
#define ICMP_ECHO_REPLY 0

struct icmp_header_ping {
    uint16_t identifier;
    uint16_t seq_no;
};

typedef struct icmp_header_ping icmp_header_ping_t;

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    icmp_header_ping_t ping_req;
    icmp_header_ping_t ping_reply;
    uint32_t pkt_len;
};

typedef struct icmp_header icmp_header_t;

#endif

