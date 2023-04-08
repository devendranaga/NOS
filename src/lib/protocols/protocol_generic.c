/**
 * @brief - Implement Protocol parser.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <stdint.h>
#include <string.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <debug.h>
#include <firewall_common.h>

STATIC fw_event_details_t parse_l2_protocol(fw_packet_t *pkt,
                                            uint16_t ethertype)
{
    fw_event_details_t type = FW_EVENT_DESCR_DENY;

    /*
     * Scan through each ethertype supported and call the
     * corresponding callback.
     */
    switch (ethertype) {
        case FW_ETHERTYPE_ARP:
            type = arp_deserialize(pkt);
        break;
        case FW_ETHERTYPE_IPV4:
            type = ipv4_deserialize(pkt);
        break;
        case FW_ETHERTYPE_IPV6:
            type = ipv6_deserialize(pkt);
        break;
        case FW_ETHERTYPE_PTP:
            type = ptp_deserialize(pkt);
        break;
        default:
            type = FW_EVENT_DESCR_ETH_UNSPPORTED_ETHERTYPE;
        break;
    }

    return type;
}

STATIC fw_event_details_t __parse_l4_protocol(fw_packet_t *pkt, bool is_ipv6, uint8_t protocol)
{
    fw_event_details_t type = FW_EVENT_DESCR_IPV4_UNSUPPORTED_PROTOCOL;

    switch (protocol) {
        case FW_IPV4_PROTOCOL_ICMP:
            type = icmp_deserialize(pkt);
        break;
        case FW_IPV4_PROTOCOL_UDP:
            type = udp_deserialize(pkt);
        break;
        case FW_IPV4_PROTOCOL_TCP:
            type = tcp_deserialize(pkt);
        break;
        default:
            type = FW_EVENT_DESCR_IPV4_UNSUPPORTED_PROTOCOL;
        break;
    }

    return type;
}

STATIC INLINE bool protocol_has_ethertype_ipv4(fw_packet_t *pkt)
{
    return fw_packet_get_ethertype(pkt) == FW_ETHERTYPE_IPV4;
}

STATIC INLINE bool protocol_has_ethertype_ipv6(fw_packet_t *pkt)
{
    return fw_packet_get_ethertype(pkt) == FW_ETHERTYPE_IPV6;
}

STATIC fw_event_details_t parse_l4_protocol(fw_packet_t *pkt)
{
    fw_event_details_t type = FW_EVENT_DESCR_IPV4_UNSUPPORTED_PROTOCOL;

    if (protocol_has_ethertype_ipv4(pkt)) {
        type = __parse_l4_protocol(pkt, false, pkt->ipv4_h.protocol);
    } else if (protocol_has_ethertype_ipv6(pkt)) {
        type = __parse_l4_protocol(pkt, true, pkt->ipv6_h.next_header);
    }

    return type;
}

fw_event_details_t parse_protocol(fw_packet_t *pkt)
{
    fw_event_details_t type;
    uint16_t ethertype;

    type = ethernet_deserialize(pkt);
    if (type == FW_EVENT_DESCR_ALLOW) {

        ethertype = pkt->eh.ethertype;
        if (pkt->eh.ethertype == FW_ETHERTYPE_VLAN) {
            vlan_deserialize(pkt);
            ethertype = pkt->vlan_h.ethertype;
        }
        type = parse_l2_protocol(pkt, ethertype);
        /* L3 is covered in ipv4. */
        if (type == FW_EVENT_DESCR_ALLOW) {
            type = parse_l4_protocol(pkt);
        }
    }

    return type;
}

void fw_pkt_copy_macaddr(fw_packet_t *pkt, uint8_t *mac)
{
    memcpy(mac, pkt->msg + pkt->off, FW_MACADDR_LEN);
    pkt->off += FW_MACADDR_LEN;
}

void fw_pkt_copy_2_bytes(fw_packet_t *pkt, uint16_t *val)
{
    *val = (pkt->msg[pkt->off] << 8) | (pkt->msg[pkt->off + 1]);
    pkt->off += 2;
}

void fw_pkt_encode_2_bytes(fw_packet_t *pkt, uint16_t val)
{
    pkt->msg[pkt->off]      = (val & 0xFF00) >> 8;
    pkt->msg[pkt->off + 1]  = (val & 0x00FF);
    pkt->off += 2;
}

void fw_pkt_copy_byte(fw_packet_t *pkt, uint8_t *val)
{
    *val = pkt->msg[pkt->off];
    pkt->off ++;
}

bool fw_pkt_has_bit_set(fw_packet_t *pkt, uint32_t pos)
{
    return !!(pkt->msg[pkt->off] & (1 << pos));
}

void fw_pkt_copy_4_bytes(fw_packet_t *pkt, uint32_t *val)
{
    *val = (pkt->msg[pkt->off]      << 24) |
           (pkt->msg[pkt->off + 1]  << 16) |
           (pkt->msg[pkt->off + 2] << 8)   |
           (pkt->msg[pkt->off + 3]);
    pkt->off += 4;
}

void fw_pkt_copy_6_bytes(fw_packet_t *pkt, uint8_t *val)
{
    uint32_t i;

    for (i = 0; i < 6; i ++) {
        val[i] = pkt->msg[pkt->off + i];
    }
    pkt->off += 6;
}

void fw_pkt_copy_6_bytes_u64(fw_packet_t *pkt, uint64_t *val)
{
    *val = ((uint64_t)(pkt->msg[pkt->off]) << 40)       |
           ((uint64_t)(pkt->msg[pkt->off + 1]) << 32)   |
           (pkt->msg[pkt->off + 2] << 24)               |
           (pkt->msg[pkt->off + 3] << 16)               |
           (pkt->msg[pkt->off + 4] << 8)                |
           (pkt->msg[pkt->off + 5]);
    pkt->off += 6;
}

void fw_pkt_copy_8_bytes(fw_packet_t *pkt, uint8_t *val)
{
    uint32_t i;

    for (i = 0; i < 8; i ++) {
        val[i] = pkt->msg[pkt->off + i];
    }
    pkt->off += 8;
}

void fw_pkt_copy_16_bytes(fw_packet_t *pkt, uint8_t *val)
{
    uint32_t i;

    for (i = 0; i < 16; i ++) {
        val[i] = pkt->msg[pkt->off + i];
    }
    pkt->off += 16;
}

