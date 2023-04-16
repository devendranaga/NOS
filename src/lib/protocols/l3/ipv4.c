/**
 * @brief - Implement Deserialization of IPv4 header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <ipv4.h>
#include <firewall_common.h>
#include <debug.h>

#define IPV4_VERSION                    4
#define IPV4_HDR_LEN_DEFAULT            5

#define IPV4_FLAGS_RESERVED_BIT         7
#define IPV4_FLAGS_DONT_FRAGMENT_BIT    6
#define IPV4_FLAGS_MORE_FRAGMENT_BIT    5

#ifdef ENABLE_PROTOCOL_PRINTS
STATIC void ipv4_print(ipv4_header_t *hdr)
{
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "ipv4: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t version: %d\n", hdr->version);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t header_len: %d\n", hdr->header_len);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t dscp: %d\n", hdr->dscp);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t ecn: %d\n", hdr->ecn);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t total_len: %d\n", hdr->total_len);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t identification: 0x%04x\n", hdr->identification);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t flags: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t reserved: %d\n", hdr->reserved);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t dont_fragment: %d\n", hdr->dont_fragment);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t more_fragment: %d\n", hdr->more_fragment);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t }\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t frag_off: %d\n", hdr->frag_off);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t ttl: %d\n", hdr->ttl);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t protocol: %d\n", hdr->protocol);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t hdr_chksum: 0x%04x\n", hdr->hdr_chksum);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t src_ipaddr: 0x%08x\n", hdr->src_ipaddr);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t dst_ipaddr: 0x%08x\n", hdr->dst_ipaddr);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "}\n");
}
#endif

fw_event_details_t ipv4_deserialize(fw_packet_t *pkt)
{
    fw_event_details_t type = FW_EVENT_DESCR_ALLOW;

    pkt->ipv4_h.start_off = pkt->off;

    /* Check if version is 4. */
    pkt->ipv4_h.version = (pkt->msg[pkt->off] & 0xF0) >> 4;
    if (pkt->ipv4_h.version != IPV4_VERSION) {
        return FW_EVENT_DESCR_IPV4_INVAL_VERSION;
    }

    /* Too small IPv4 header length. */
    pkt->ipv4_h.header_len = (pkt->msg[pkt->off] & 0x0F);
    if (pkt->ipv4_h.header_len < IPV4_HDR_LEN_DEFAULT) {
        return FW_EVENT_DESCR_IPV4_HDR_LEN_TOO_SMALL;
    }

    pkt->off ++;

    pkt->ipv4_h.dscp = (pkt->msg[pkt->off] & 0xFC) >> 2;
    pkt->ipv4_h.ecn = (pkt->msg[pkt->off] & 0x03);

    pkt->off ++;

    fw_pkt_copy_2_bytes(pkt, &pkt->ipv4_h.total_len);
    fw_pkt_copy_2_bytes(pkt, &pkt->ipv4_h.identification);

    /* Check if Reserved bit is set. */
    pkt->ipv4_h.reserved = fw_pkt_has_bit_set(pkt,
                                    IPV4_FLAGS_RESERVED_BIT);
    if (pkt->ipv4_h.reserved) {
        return FW_EVENT_DESCR_IPV4_FLAGS_RESERVED_SET;
    }

    /* Check if both MF DF bits are set. */
    pkt->ipv4_h.dont_fragment = fw_pkt_has_bit_set(pkt,
                                    IPV4_FLAGS_DONT_FRAGMENT_BIT);
    pkt->ipv4_h.more_fragment = fw_pkt_has_bit_set(pkt,
                                    IPV4_FLAGS_MORE_FRAGMENT_BIT);
    if (pkt->ipv4_h.dont_fragment &&
        pkt->ipv4_h.more_fragment) {
        return FW_EVENT_DESCR_IPV4_FLAGS_BOTH_MF_DF_SET;
    }

    pkt->ipv4_h.frag_off = (((pkt->msg[pkt->off] & 0x1F) << 8) |
                            (pkt->msg[pkt->off + 1]));
    pkt->off += 2;

    /* Check if TTL is 0. */
    fw_pkt_copy_byte(pkt, &pkt->ipv4_h.ttl);
    if (pkt->ipv4_h.ttl == 0) {
        return FW_EVENT_DESCR_IPV4_TTL_ZERO;
    }

    fw_pkt_copy_byte(pkt, &pkt->ipv4_h.protocol);
    fw_pkt_copy_2_bytes(pkt, &pkt->ipv4_h.hdr_chksum);
    fw_pkt_copy_4_bytes(pkt, &pkt->ipv4_h.src_ipaddr);
    fw_pkt_copy_4_bytes(pkt, &pkt->ipv4_h.dst_ipaddr);

    pkt->ipv4_h.stop_off = pkt->off;

    ipv4_print(&pkt->ipv4_h);
    return type;
}

bool ipv4_pkt_has_fragments(ipv4_header_t *hdr)
{
    return hdr->more_fragment;
}

bool ipv4_pkt_validate_checksum(fw_packet_t *pkt)
{
    uint32_t val = 0;
    int carry = 0;
    uint32_t i = 0;

    /* Append all two bytes together. */
    for (i = pkt->ipv4_h.start_off; i < pkt->ipv4_h.stop_off; i += 2) {
        val += ((pkt->msg[i + 1] << 8) | (pkt->msg[i]));
    }

    /* Find the carry if overflow 0xFFFF. */
    carry = (val & 0xFF0000) >> 16;
    val = val & 0xFFFF;

    /* A combined value must reach 0xFFFF. */
    if ((val + carry) == 0xFFFF) {
        return true;
    }

    return false;
}

