/**
 * @brief - Implements VLAN parsing and serialization.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>
#include <debug.h>

#ifdef ENABLE_PROTOCOL_PRINTS
STATIC void vlan_print(vlan_header_t *vlan_hdr)
{
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "vlan: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t pcp: %d\n", vlan_hdr->pcp);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t dei: %d\n", vlan_hdr->dei);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t vid: %d\n", vlan_hdr->vid);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t ethertype: 0x%04x\n",
                                        vlan_hdr->ethertype);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "}\n");
}
#endif

fw_event_details_t vlan_deserialize(fw_packet_t *pkt)
{
    pkt->vlan_h.pcp = (pkt->msg[pkt->off] & 0xE0) >> 5;
    pkt->vlan_h.dei = fw_pkt_has_bit_set(pkt, 4);
    pkt->vlan_h.vid = ((pkt->msg[pkt->off] & 0x0F) << 4 |
                (pkt->msg[pkt->off + 1]));
    pkt->off += 2;

    fw_pkt_copy_2_bytes(pkt, &pkt->vlan_h.ethertype);

    vlan_print(&pkt->vlan_h);

    return FW_EVENT_DESCR_ALLOW;
}

