/**
 * @brief - Implements DNS header parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <firewall_common.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <dns.h>

fw_event_details_t dns_deserialize(fw_packet_t *pkt)
{
    uint16_t flags;

    fw_pkt_copy_2_bytes(pkt, &pkt->dns_h.transaction_id);
    fw_pkt_copy_2_bytes(pkt, &flags);
    pkt->dns_h.flags_response = !!(flags & 0x8000);
    pkt->dns_h.flags_opcode = (flags & 0x7800) >> 11;
    pkt->dns_h.flags_truncated = !!(flags & 0x0200);
    pkt->dns_h.flags_recursion_denied = !!(flags & 0x0100);
    pkt->dns_h.flags_z = !!(flags & 0x0040);
    pkt->dns_h.flags_non_auth_data = !!(flags & 0x0010);
    fw_pkt_copy_2_bytes(pkt, &pkt->dns_h.questions);
    fw_pkt_copy_2_bytes(pkt, &pkt->dns_h.answer_rr);
    fw_pkt_copy_2_bytes(pkt, &pkt->dns_h.authority_rr);
    fw_pkt_copy_2_bytes(pkt, &pkt->dns_h.additional_rr);

    if (pkt->msg[pkt->off] == 0x05) {
        pkt->off ++;

        fw_pkt_copy_16_bytes(pkt, (uint8_t *)(pkt->dns_h.queries[0].name));
        fw_pkt_copy_2_bytes(pkt, &pkt->dns_h.queries[0].label_type);
        fw_pkt_copy_2_bytes(pkt, &pkt->dns_h.queries[0].label_class);
    }

    return FW_EVENT_DESCR_ALLOW;
}

