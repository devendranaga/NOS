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

#define DOIP_TYPE_VEH_ANNOUNCEMENT  0x0004
#define DOIP_TYPE_DIAGNOSTICS_MSG   0x8001

namespace nos::firewall
{

struct doip_veh_announcement_msg {
    uint8_t     vin[17];
    uint16_t    logical_addr;
    uint8_t     eid[6];
    uint8_t     gid[6];
    uint8_t     further_action_required;
};

#define DOIP_DIAG_SESSION_CTRL 0x10

struct uds_diagnostics_session_control {
    uint8_t type;
};

struct doip_diagnostics_msg {
    uint16_t    source_addr;
    uint16_t    target_addr;
    uint8_t     service_id;
    bool        reply_flag;

    uds_diagnostics_session_control sess_ctrl;
};

struct doip_header {
    uint8_t     version;
    uint8_t     inv_version;
    uint16_t    type;
    uint32_t    len;
    doip_veh_announcement_msg announcement;
    doip_diagnostics_msg diag;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

}

#endif
