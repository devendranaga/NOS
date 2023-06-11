/**
 * @brief - Implements udp.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_PACKET_UDP_H__
#define __NOS_PACKET_UDP_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

struct udp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

}

#endif
