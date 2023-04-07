#ifndef __LIB_PROTOCOL_UDP_H__
#define __LIB_PROTOCOL_UDP_H__

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

typedef struct udp_header udp_header_t;

#endif

