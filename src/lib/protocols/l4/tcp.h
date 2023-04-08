#ifndef __LIB_PROTOCOLS_TCP_H__
#define __LIB_PROTOCOLS_TCP_H__

#include <stdint.h>
#include <stdbool.h>

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_no;
    uint32_t ack_no;
    uint8_t data_offset;
    uint8_t reserved;
    uint8_t flags;
    bool cwr;
    bool ece;
    bool urg;
    bool ack;
    bool psh;
    bool rst;
    bool syn;
    bool fin;
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urg_pointer;
};

typedef struct tcp_header tcp_header_t;

#endif
