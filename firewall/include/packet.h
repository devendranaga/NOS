#ifndef __NOS_PACKET_H__
#define __NOS_PACKET_H__

#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <event_types.h>
#include <packet-buf.h>
#include <packet-eth.h>
#include <packet-arp.h>
#include <packet-ipv4.h>
#include <packet-icmp.h>

#define PACKET_BUF_MAX_DATA_LEN 8192

#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_IPV6      0x86DD

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
