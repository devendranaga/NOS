/**
 * @brief - Implement Deserialization of IPv4 header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <ipv6.h>
#include <firewall_common.h>
#include <debug.h>

#define IPV6_HDR_VERSION_TC_FLOW_LABLE 4

#ifdef ENABLE_PROTOCOL_PRINTS
STATIC void ipv6_print(ipv6_header_t *hdr)
{
    uint32_t i;

    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "ipv6: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t version: %d\n", hdr->version);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t tc: %d\n", hdr->tc);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t flow_label: %d\n", hdr->flow_label);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t payload_len: %d\n", hdr->payload_len);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t next_header: %d\n", hdr->next_header);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t hoplimit: %d\n", hdr->hoplimit);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t src_ipv6addr: {\n\t ");
    for (i = 0; i < sizeof(hdr->src_ip6addr); i ++) {
        fprintf(stderr, "%02x ", hdr->src_ip6addr[i]);
    }
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t }\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t dst_ipv6addr: {\n\t ");
    for (i = 0; i < sizeof(hdr->dst_ip6addr); i ++) {
        fprintf(stderr, "%02x ", hdr->dst_ip6addr[i]);
    }
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t }\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "}\n");
}
#endif

STATIC uint32_t ipv6_min_hdrlen(ipv6_header_t *hdr)
{
    return IPV6_HDR_VERSION_TC_FLOW_LABLE +
           sizeof(hdr->payload_len) +
           sizeof(hdr->next_header) +
           sizeof(hdr->hoplimit) +
           sizeof(hdr->src_ip6addr) +
           sizeof(hdr->dst_ip6addr);
}

fw_event_details_t ipv6_deserialize(fw_packet_t *pkt)
{
    if ((pkt->total_len - pkt->off) < ipv6_min_hdrlen(&pkt->ipv6_h)) {
        return FW_EVENT_DESCR_IPV6_HDRLEN_TOO_SMALL;
    }

    pkt->ipv6_h.version = (pkt->msg[pkt->off] & 0xF0) >> 4;
    pkt->ipv6_h.tc = (pkt->msg[pkt->off] & 0x0F) |
                     (pkt->msg[pkt->off + 1] & 0xF0);
    pkt->off ++;

    pkt->ipv6_h.flow_label = ((pkt->msg[pkt->off] & 0x0F) << 12) |
                             (pkt->msg[pkt->off + 1]) << 8 |
                             (pkt->msg[pkt->off + 2]);
    pkt->off += 3;

    fw_pkt_copy_2_bytes(pkt, &pkt->ipv6_h.payload_len);
    fw_pkt_copy_byte(pkt, &pkt->ipv6_h.next_header);
    fw_pkt_copy_byte(pkt, &pkt->ipv6_h.hoplimit);
    fw_pkt_copy_16_bytes(pkt, pkt->ipv6_h.src_ip6addr);
    fw_pkt_copy_16_bytes(pkt, pkt->ipv6_h.dst_ip6addr);

    ipv6_print(&pkt->ipv6_h);

    return FW_EVENT_DESCR_ALLOW;
}

