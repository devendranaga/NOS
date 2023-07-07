/**
 * @brief - Implements NTP V4 header parsing.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_PACKET_NTP_H__
#define __NOS_PACKET_NTP_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>
#include <nos_core.h>

namespace nos::firewall
{

struct ntp_v4_header {
    uint8_t leap_indicator:2;
    uint8_t version:3;
    uint8_t mode:3;
    uint8_t peer_clock_stratum;
    uint8_t peer_clock_poll_interval;
    uint8_t peer_clock_precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_id;
    uint64_t reference_timestamp;
    uint64_t origin_timestamp;
    uint64_t receive_timestamp;
    uint64_t transmit_timestamp;
    uint32_t keyid;
    uint8_t mac[16];

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

}

#endif
