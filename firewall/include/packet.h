#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <event_types.h>

#define PACKET_BUF_MAX_DATA_LEN 8192
#define MACADDR_LEN 6

#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_IPV4      0x0800

namespace nos::firewall {

struct packet_buf {
    uint8_t *data;
    uint32_t data_len;
    uint32_t off;

    explicit packet_buf(uint16_t data_len) {
    }
    explicit packet_buf() : data(NULL), data_len(0), off(0) { }
    ~packet_buf() { }

    event_type deserialize_byte(uint8_t *byte);
    event_type deserialize_2_bytes(uint16_t *bytes);
    event_type deserialize_4_bytes(uint32_t *bytes);
    event_type deserialize_8_bytes(uint64_t *bytes);
    event_type deserilaize_mac(uint8_t *macaddr);
    event_type deserialize_ipaddr(uint32_t *ipaddr);
    event_type deserialize_ip6addr(uint8_t *ip6addr, uint16_t *len);
    event_type deserialize_bytes(uint8_t *bytes, uint32_t len);
    event_type skip_bytes(uint32_t len);
};

struct ether_header {
    uint8_t         srcmac[MACADDR_LEN];
    uint8_t         dstmac[MACADDR_LEN];
    uint16_t        ethertype;

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct vlan_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct ieee8021ae_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct ieee8021x_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

#define ARP_OP_ARP_REQ          1
#define ARP_OP_ARP_REPLY        2
#define ARP_OP_RARP_REQ         3
#define ARP_OP_RARP_REPLY       4
#define ARP_OP_DRARP_REQ        5
#define ARP_OP_DRARP_REPLY      6
#define ARP_OP_DRARP_ERROR      7
#define ARP_OP_INARP_REQ        8
#define ARP_OP_INARP_REPLY      9

#define ARP_HEADER_LEN          28

struct arp_header {
    uint16_t        header_type;
    uint16_t        protocol_type;
    uint8_t         hwaddr_len;
    uint8_t         protoaddr_len;
    uint16_t        operation;
    uint8_t         sender_hwaddr[MACADDR_LEN];
    uint32_t        sender_proto_addr;
    uint8_t         target_hwaddr[MACADDR_LEN];
    uint32_t        target_proto_addr;

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct ipv4_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct ipv6_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct icmp_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct icmp6_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct tcp_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct udp_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct ppp_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

enum tunnel_type {
    None,
    Tcp,
    Udp,
    Ipv4_In_IPv6,
    Ipv6_In_IPv4,
};

struct packet {
    packet_buf *buf;

    tunnel_type tun_type;
    ether_header *eth_h;
    vlan_header *vlan_h;
    arp_header *arp_h;
    ipv4_header *ipv4_h;
    ipv6_header *ipv6_h;
    tcp_header *tcp_h;
    udp_header *udp_h;
    icmp_header *icmp_h;
    icmp6_header *icmp6_h;
    ppp_header *ppp_h;

    std::vector<packet> tunneled_packets_;

    explicit packet() : tun_type(tunnel_type::None) { }
    ~packet() {
        if (eth_h) {
            eth_h->free_hdr();
            free(eth_h);
        }
    }

    bool has_vlan() { return vlan_h ? true : false; }
};

}
