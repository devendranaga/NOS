/**
 * @brief - Implements VLAN parsing and serialization.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>

fw_event_details_t vlan_deserialize(fw_packet_t *pkt)
{
    pkt->vlan_h.pcp = (pkt->msg[pkt->off] & 0xE0) >> 5;
    pkt->vlan_h.dei = fw_has_bit_set(pkt, 4);
    pkt->vlan_h.vid = ((pkt->msg[pkt->off] & 0x0F) << 4 |
                (pkt->msg[pkt->off + 1]));
    pkt->off += 2;

    fw_copy_2_bytes(pkt, &pkt->vlan_h.ethertype);

    return FW_EVENT_DESCR_ALLOW;
}

