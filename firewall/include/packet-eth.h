/**
 * @brief - Implements Ethernet Header.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __NOS_PACKET_ETH_H__
#define __NOS_PACKET_ETH_H__

#include <stdint.h>
#include <string.h>
#include <memory>
#include <event_types.h>
#include <packet-buf.h>
#include <nos_core.h>

namespace nos::firewall
{

#define MACADDR_LEN 6

/**
 * @brief - Defines Ethernet Header.
 */
struct ether_header {
    uint8_t         srcmac[MACADDR_LEN];
    uint8_t         dstmac[MACADDR_LEN];
    uint16_t        ethertype;

    explicit ether_header() {
        memset(zero_mac, 0, sizeof(zero_mac));
        broadcast_mac[0] = broadcast_mac[1] = 0xff;
        broadcast_mac[2] = broadcast_mac[3] = 0xff;
        broadcast_mac[4] = broadcast_mac[5] = 0xff;
    }

    /**
     * @brief - Deserialize Ethernet header.
     *
     * @param [in] buf - in buffer
     * @param [in] log - log pointer
     */
    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }

    inline bool is_src_zero_mac()
    { return memcmp(srcmac, zero_mac, MACADDR_LEN) == 0; }

    inline bool is_src_broadcast_mac()
    { return memcmp(srcmac, broadcast_mac, MACADDR_LEN) == 0; }

    inline bool is_dst_zero_mac()
    { return memcmp(dstmac, zero_mac, MACADDR_LEN) == 0; }

    inline bool is_dst_broadcast_mac()
    { return memcmp(dstmac, broadcast_mac, MACADDR_LEN) == 0; }


    private:
        uint8_t zero_mac[MACADDR_LEN];
        uint8_t broadcast_mac[MACADDR_LEN];

        void print(const std::shared_ptr<nos::core::logging> &log);
};

}

#endif
