/**
 * @brief - Implements fw_pkt header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FW_PKT_H__
#define __FW_PKT_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <os_thread.h>
#include <ethernet.h>
#include <arp.h>
#include <vlan.h>
#include <ptp.h>
#include <8021ae.h>
#include <8021x.h>
#include <ipv4.h>
#include <ipv6.h>
#include <icmp.h>
#include <icmp6.h>
#include <udp.h>
#include <tcp.h>
#include <someip.h>
#include <dhcp.h>
#include <firewall_common.h>

#define FW_PACKET_LEN_MAX 8192
#define FW_RULE_NOT_MATCHED 0xDEADBEEF

/* Define firewall packet. */
struct fw_packet {
    uint8_t msg[FW_PACKET_LEN_MAX];
    uint32_t total_len;
    uint32_t off;
    struct os_mutex lock;

    /* Ethernet Header. */
    struct ethernet_header eh;

    /* Arp Header. */
    struct arp_header arp_h;

    /* VLAN Header. */
    struct vlan_header vlan_h;

    /* PTP Header. */
    struct ptp_header ptp_h;

    /* IEEE 802.1AE MACsec Header. */
    struct ieee8021ae_hdr macsec_h;

    struct ieee8021x_header dot1x_h;

    /* IPv4 Header. */
    struct ipv4_header ipv4_h;

    /* IPv6 Header. */
    struct ipv6_header ipv6_h;

    /* ICMP Header. */
    struct icmp_header icmp_h;

    /* ICMP6 Header. */
    struct icmp6_header icmp6_h;

    /* UDP Header. */
    struct udp_header udp_h;

    /* TCP Header. */
    struct tcp_header tcp_h;

    /* SOME/IP Header. */
    struct someip_header someip_h;

    /* DHCP Header. */
    struct dhcp_header dhcp_h;

    /*
     * Matching rule for this packet.
     * FW_RULE_NOT_MATCHED if no rule is matched.
     */
    uint32_t matched_rule_id;
    bool is_layer2_ptp;

    struct fw_packet *next;
};

typedef struct fw_packet fw_packet_t;

uint16_t fw_packet_get_ethertype(fw_packet_t *pkt);
uint16_t fw_packet_get_vid(fw_packet_t *pkt);
void *fw_packet_queue_init();
void fw_packet_queue_deinit(void *);
void fw_packet_queue_entry_add(void *q, struct fw_packet *pkt);
struct fw_packet *fw_packet_queue_first(void *q);

uint32_t fw_packet_get_remaining_len(fw_packet_t *pkt);

#endif

