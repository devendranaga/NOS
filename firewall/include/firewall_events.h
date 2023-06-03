/**
 * @brief - Implements firewall events.
*/
#ifndef __NOS_FIREWALL_EVENTS_H__
#define __NOS_FIREWALL_EVENTS_H__

#include <event_types.h>
#include <packet.h>

namespace nos::firewall {

enum event_result {
    Allow,
    Deny,
};

struct firewall_event {
    char            intf[15];
    event_result    res;
    event_type      descr;
    uint32_t        rule_id;
    uint8_t         sender_mac[6];
    uint8_t         target_mac[6];
    uint16_t        ethertype;
    uint16_t        vlan_id;
    uint32_t        src_ipaddr;
    uint32_t        dest_ipaddr;
    uint8_t         src_ip6addr[16];
    uint8_t         dst_ip6addr[16];
    uint16_t        protocol;
    uint16_t        src_port;
    uint16_t        dst_port;

    packet_buf      pkt;
};

}

#endif
