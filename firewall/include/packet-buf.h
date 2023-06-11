#ifndef __NOS_PACKET_BUF_H__
#define __NOS_PACKET_BUF_H__

#include <stdint.h>
#include <event_types.h>
#include <string>

namespace nos::firewall
{

struct packet_buf {
    std::string intf;
    uint8_t *data;
    uint32_t data_len;
    uint32_t off;

    explicit packet_buf(uint16_t data_len) {
    }
    explicit packet_buf(std::string if_name): intf(if_name) { }
    explicit packet_buf() : data(nullptr), data_len(0), off(0) { }
    ~packet_buf() { }

    event_type deserialize_byte(uint8_t *byte);
    event_type deserialize_2_bytes(uint16_t *bytes);
    event_type deserialize_4_bytes(uint32_t *bytes);
    event_type deserialize_8_bytes(uint64_t *bytes);
    event_type deserilaize_mac(uint8_t *macaddr);
    event_type deserialize_ipaddr(uint32_t *ipaddr);
    event_type deserialize_ip6addr(uint8_t *ip6addr);
    event_type deserialize_bytes(uint8_t *bytes, uint32_t len);
    event_type skip_bytes(uint32_t len);
};

}

#endif
