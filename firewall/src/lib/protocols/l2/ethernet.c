/**
 * @brief - Implements Ethernet parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <stdio.h>
#include <string.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <ethernet.h>
#include <debug.h>
#include <firewall_common.h>

STATIC CONST uint8_t zero[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
STATIC CONST uint8_t broadcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

STATIC bool mac_zeros(uint8_t *src, uint8_t *dst)
{
    if ((memcmp(src, zero, sizeof(zero)) == 0) &&
        (memcmp(dst, zero, sizeof(zero)) == 0)) {
        return true;
    }

    return false;
}

STATIC bool mac_broadcast(uint8_t *src, uint8_t *dst)
{
    if ((memcmp(src, broadcast, sizeof(broadcast)) == 0) &&
        (memcmp(dst, broadcast, sizeof(broadcast)) == 0)) {
        return true;
    }

    return false;
}

#ifdef ENABLE_PROTOCOL_PRINTS
STATIC void ethernet_print(struct ethernet_header *eh)
{
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "eth: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                     eh->dst[0], eh->dst[1],
                                     eh->dst[2], eh->dst[3],
                                     eh->dst[4], eh->dst[5]);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t src: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                     eh->src[0], eh->src[1],
                                     eh->src[2], eh->src[3],
                                     eh->src[4], eh->src[5]);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t ethertype: 0x%04x\n", eh->ethertype);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "}\n");
}
#endif

fw_event_details_t ethernet_deserialize(fw_packet_t *hdr)
{
    fw_event_details_t type = FW_EVENT_DESCR_ALLOW;

    fw_pkt_copy_macaddr(hdr, hdr->eh.dst);
    fw_pkt_copy_macaddr(hdr, hdr->eh.src);
    fw_pkt_copy_2_bytes(hdr, &hdr->eh.ethertype);

    /* Deny if both src and dst are 0s. */
    if (mac_zeros(hdr->eh.src, hdr->eh.dst) == true) {
        return FW_EVENT_DESCR_ETH_SRC_DST_ARE_ZERO;
    }

    /* Deny if both src and dst are broadcast. */
    if (mac_broadcast(hdr->eh.src, hdr->eh.dst) == true) {
        return FW_EVENT_DESCR_ETH_SRC_DST_ARE_BROADCAST;
    }

    ethernet_print(&hdr->eh);

    return type;
}

fw_event_details_t ethernet_serialize(fw_packet_t *hdr)
{
    memcpy(hdr->msg, hdr->eh.dst, sizeof(hdr->eh.dst));
    hdr->off += sizeof(hdr->eh.dst);

    memcpy(hdr->msg + hdr->off, hdr->eh.src, sizeof(hdr->eh.src));
    hdr->off += sizeof(hdr->eh.src);

    fw_pkt_encode_2_bytes(hdr, hdr->eh.ethertype);

    return FW_EVENT_DESCR_ALLOW;
}

