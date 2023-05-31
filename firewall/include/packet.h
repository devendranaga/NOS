#include <stdlib.h>
#include <stdint.h>
#include <event_types.h>

#define PACKET_BUF_MAX_DATA_LEN 8192
#define MACADDR_LEN 6

namespace nos::firewall {

struct packet_buf {
    uint8_t *data;
    uint32_t data_len;
    uint32_t off;

    explicit packet_buf(uint16_t data_len) {
    }
    explicit packet_buf() : data(NULL), data_len(0), off(0) { }
    ~packet_buf() { }

    int deserialize_byte(uint8_t *byte);
    int deserialize_2_bytes(uint16_t *bytes);
    int deserialize_4_bytes(uint32_t *bytes);
    int deserialize_8_bytes(uint64_t *bytes);
    int deserilaize_mac(uint8_t *macaddr);
    int deserialize_ipaddr(uint32_t *ipaddr);
    int deserialize_ip6addr(uint8_t *ip6addr, uint16_t *len);
    int deserialize_bytes(uint8_t *bytes, uint32_t len);
};

struct ether_header {
    uint8_t srcmac[MACADDR_LEN];
    uint8_t dstmac[MACADDR_LEN];
    uint16_t ethertype;

    event_type deserialize(packet_buf &buf);
};

struct arp_header {

};

struct ipv4_header {

};

struct packet {
    packet_buf *buf;

    ether_header eh;
    arp_header ah;
};

}
