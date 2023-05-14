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
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t checksum: %s\n",
                        icmp_h->checksum_ok ? "Ok": "Not Ok");
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

STATIC uint32_t icmp_get_min_hdrlen(icmp_header_t *icmp_h)
{
    return sizeof(icmp_h->code) +
           sizeof(icmp_h->type) +
           sizeof(icmp_h->checksum) +
           sizeof(icmp_h->ping_req);
}

STATIC bool icmp_validate_checksum(fw_packet_t *pkt, uint32_t hdr_off)
{
    uint32_t total_len = pkt->total_len;
    uint32_t carry = 0;
    uint32_t data = 0;
    uint32_t i = 0;

    /* Round to nearest even number. */
    if (pkt->total_len % 2 != 0) {
        total_len += 1;
    }

    /*
     * Checksum is calculated as value checked from
     * icmp->header till the last byte of the payload.
     *
     * Each two bytes are added up to reach the final checksum.
     */
    for (i = hdr_off; i < total_len; i += 2) {
        data += ((pkt->msg[i + 1] << 8) | pkt->msg[i]);
    }

    carry = (data & 0xFF0000) >> 16;
    data = data & 0xFFFF;

    if (data + carry == 0xFFFF) {
        return true;
    }

    return false;
}

fw_event_details_t icmp_deserialize(fw_packet_t *pkt)
{
    uint32_t start_off = 0;
    fw_event_details_t type = FW_EVENT_DESCR_ICMP_INVAL;

    start_off = pkt->off;

    /* Validate and drop if ICMP header length is too small. could be a
     * bad formed packet or test from a sender.
     */
    if ((pkt->total_len - pkt->off) < icmp_get_min_hdrlen(&pkt->icmp_h)) {
        return FW_EVENT_DESCR_ICMP_HDR_TOO_SMALL;
    }

    fw_pkt_copy_byte(pkt, &pkt->icmp_h.type);
    fw_pkt_copy_byte(pkt, &pkt->icmp_h.code);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp_h.checksum);

    if (pkt->icmp_h.type == ICMP_ECHO_REQ) {
        type = icmp_parse_echo_req(pkt);
    } else if (pkt->icmp_h.type == ICMP_ECHO_REPLY) {
        type = icmp_parse_echo_reply(pkt);
    } else {
        type = FW_EVENT_DESCR_ICMP_UNSUPPORTED_TYPE;
    }

    if (type == FW_EVENT_DESCR_ALLOW) {
        pkt->icmp_h.pkt_len = fw_packet_get_remaining_len(pkt);
    }

    pkt->icmp_h.checksum_ok = icmp_validate_checksum(pkt, start_off);
    if (pkt->icmp_h.checksum_ok == false) {
        type = FW_EVENT_DESCR_ICMP_HDR_CHECKSUM_FAILED;
    }

    icmp_print(&pkt->icmp_h);

    return type;
}

