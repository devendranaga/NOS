#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>
#include <debug.h>

#ifdef ENABLE_PROTOCOL_PRINTS
STATIC void icmp_print(struct icmp_header *icmp_h)
{
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "icmp: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t type: %d\n", icmp_h->type);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t code: %d\n", icmp_h->code);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t checksum: 0x%04x\n", icmp_h->checksum);
    if (icmp_h->type == ICMP_ECHO_REQ) {
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t echo_req: {\n");
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t 0x%04x\n", icmp_h->ping_req.identifier);
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t 0x%04x\n", icmp_h->ping_req.seq_no);
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t }\n");
    } else if (icmp_h->type == ICMP_ECHO_REPLY) {
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t echo_reply: {\n");
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t 0x%04x\n", icmp_h->ping_reply.identifier);
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t 0x%04x\n", icmp_h->ping_reply.seq_no);
        fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t }\n");
    }
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "}\n");
}
#endif

STATIC fw_event_details_t icmp_parse_echo_req(fw_packet_t *pkt)
{
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp_h.ping_req.identifier);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp_h.ping_req.seq_no);

    return FW_EVENT_DESCR_ALLOW;
}

STATIC fw_event_details_t icmp_parse_echo_reply(fw_packet_t *pkt)
{
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp_h.ping_reply.identifier);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp_h.ping_reply.seq_no);

    return FW_EVENT_DESCR_ALLOW;
}

fw_event_details_t icmp_deserialize(fw_packet_t *pkt)
{
    fw_event_details_t type = FW_EVENT_DESCR_ICMP_INVAL;

    fw_pkt_copy_byte(pkt, &pkt->icmp_h.type);
    fw_pkt_copy_byte(pkt, &pkt->icmp_h.code);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp_h.checksum);

    if (pkt->icmp_h.type == ICMP_ECHO_REQ) {
        type = icmp_parse_echo_req(pkt);
    } else if (pkt->icmp_h.type == ICMP_ECHO_REPLY) {
        type = icmp_parse_echo_reply(pkt);
    }

    icmp_print(&pkt->icmp_h);

    return type;
}

