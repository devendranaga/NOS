/**
 * @brief - implements DoIP packet header.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_PACKET_DOIP_H__
#define __NOS_PACKET_DOIP_H__

#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <event_types.h>
#include <packet-buf.h>
#include <nos_core.h>

#define PACKET_DOIP_PORT 13400

#define DOIP_TYPE_VEH_ANNOUNCEMENT 0x0004

namespace nos::firewall
{

struct doip_veh_announcement_msg {
    uint8_t     vin[17];
    uint16_t    logical_addr;
    uint8_t     eid[6];
    uint8_t     gid[6];
    uint8_t     further_action_required;
};

struct doip_header {
    uint8_t     version;
    uint8_t     inv_version;
    uint16_t    type;
    uint32_t    len;
    doip_veh_announcement_msg announcement;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

}

#endif
