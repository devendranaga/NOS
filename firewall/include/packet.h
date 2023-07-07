/**
 * @brief - implements packet header.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_PACKET_H__
#define __NOS_PACKET_H__

#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <event_types.h>
#include <packet-buf.h>
#include <packet-eth.h>
#include <packet-arp.h>
#include <packet-ieee8021ae.h>
#include <packet-ipv4.h>
#include <packet-ipv6.h>
#include <packet-icmp.h>
#include <packet-icmp6.h>
#include <packet-udp.h>
#include <packet-doip.h>
#include <packet-tcp.h>
#include <packet-ntp.h>
#include <packet-ptp.h>

#define PACKET_BUF_MAX_DATA_LEN 8192

#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_IPV6      0x86DD
#define ETHERTYPE_MACSEC    0x88E5

#define PROTOCOL_UDP        0x11
#define PROTOCOL_ICMP       0x01
#define PROTOCOL_TCP        0x06
#define PROTOCOL_ICMP6      0x3A

#define PORT_PTP            319

namespace nos::firewall {

struct vlan_header {
    event_type deserialize(packet_buf &buf);
    void free_hdr() { }
};

struct ieee8021x_mka_basic_parameters {

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka_live_parameters {

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka_potential_parameters {

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka_distr_sak {

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka_sak_use {

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka_icv {

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka_announcement {

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka_xpn {
    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_mka {
    ieee8021x_mka_basic_parameters bp;
    ieee8021x_mka_live_parameters lp;
    ieee8021x_mka_potential_parameters pp;
    ieee8021x_mka_distr_sak distr_sak;
    ieee8021x_mka_sak_use sak_use;
    ieee8021x_mka_icv icv;
    ieee8021x_mka_announcement announcement;
    ieee8021x_mka_xpn xpn;

    event_type deserialize(packet_buf &buf);
};

struct ieee8021x_header {
    ieee8021x_mka mka;

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
    ieee8021ae_header macsec_h;
    ipv4_header ipv4_h;
    ipv6_header ipv6_h;
    tcp_header tcp_h;
    udp_header udp_h;
    icmp_header icmp_h;
    icmp6_header icmp6_h;
    ppp_header ppp_h;
    doip_header doip_h;

    std::vector<packet> tunneled_packets_;

    explicit packet() : tun_type(tunnel_type::None) { }
    ~packet() { }

    uint32_t get_tunnel_size() { return tunneled_packets_.size(); }
};

struct packet_parser_state {
    packet_buf pkt_buf;
    packet pkt;
};

}

#endif
