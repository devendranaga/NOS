#ifndef __NOS_PACKET_H__
#define __NOS_PACKET_H__

#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <event_types.h>
#include <packet-buf.h>
#include <packet-eth.h>
#include <packet-icmp.h>

#define PACKET_BUF_MAX_DATA_LEN 8192

#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_IPV4      0x0800

namespace nos::firewall {

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

/**
 * @brief - Implements ARP header.
 */
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

    inline bool is_arp_req() { return operation == ARP_OP_ARP_REQ; }
    inline bool is_arp_reply() { return operation == ARP_OP_ARP_REPLY; }
    inline bool is_proto_ipv4() { return protocol_type == UNSUPPORTED_ETHERTYPE; }

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

#define IPV4_VERSION 4
#define IPV4_IHL_LEN_MIN 5
#define IPV4_IHL_LEN_MAX 15

/**
 * @brief - Implements ipv4 header.
 */
struct ipv4_header {
    uint8_t         version;
    uint8_t         ihl;
    uint8_t         dscp;
    uint8_t         ecn;
    uint16_t        total_len;
    uint16_t        id;
    uint8_t         flags_reserved:1;
    uint8_t         flags_dont_fragment:1;
    uint8_t         flags_more_fragment:1;
    uint16_t        frag_off;
    uint8_t         ttl;
    uint8_t         protocol;
    uint16_t        hdr_chksum;
    uint32_t        source_ipaddr;
    uint32_t        dest_ipaddr;
    bool            header_parsed_ok;

    event_type deserialize(packet_buf &buf);
    void free_hdr() { }

    inline bool has_fragment()
    { return (flags_more_fragment == 1) || (frag_off != 0); }
};

struct ipv6_header {
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
    tunnel_type tun_type;
    ether_header eth_h;
    vlan_header vlan_h;
    arp_header arp_h;
    ipv4_header ipv4_h;
    ipv6_header ipv6_h;
    tcp_header tcp_h;
    udp_header udp_h;
    icmp_header icmp_h;
    icmp6_header icmp6_h;
    ppp_header ppp_h;

    std::vector<packet> tunneled_packets_;

    explicit packet() : tun_type(tunnel_type::None) { }
    ~packet() { }
};

struct packet_parser_state {
    packet_buf pkt_buf;
    packet pkt;
};

}

#endif
