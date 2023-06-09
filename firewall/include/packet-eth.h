#ifndef __NOS_PACKET_ETH_H__
#define __NOS_PACKET_ETH_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

#define MACADDR_LEN 6

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
    event_type deserialize(packet_buf &buf);
    void print();
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
};

}

#endif
