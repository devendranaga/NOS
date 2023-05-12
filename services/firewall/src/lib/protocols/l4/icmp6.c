#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>
#include <debug.h>

#ifdef ENABLE_PROTOCOL_PRINTS
void icmp6_print(icmp6_header_t *hdr)
{

}
#endif

STATIC void icmp6_deserialize_echo_req(fw_packet_t *pkt)
{
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp6_h.ping_req.id);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp6_h.ping_req.seq);
}

STATIC void icmp6_deserialize_echo_reply(fw_packet_t *pkt)
{
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp6_h.ping_reply.id);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp6_h.ping_reply.seq);
}

STATIC uint16_t icmp6_min_hdrlen(fw_packet_t *pkt)
{
    return sizeof(pkt->icmp6_h.type) +
           sizeof(pkt->icmp6_h.code) +
           sizeof(pkt->icmp6_h.checksum) +
           sizeof(pkt->icmp6_h.ping_req.id) +
           sizeof(pkt->icmp6_h.ping_req.seq);
}

STATIC void icmp6_deserialize_neighbor_solicitation(fw_packet_t *pkt)
{
    fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.ns.reserved);
    fw_pkt_copy_16_bytes(pkt, pkt->icmp6_h.ns.target_addr);

    if (pkt->msg[pkt->off] == 0x0e) { /* Nonce. */
        fw_pkt_copy_byte(pkt, &pkt->icmp6_h.ns.opt.type);
        fw_pkt_copy_byte(pkt, &pkt->icmp6_h.ns.opt.len);
        fw_pkt_copy_n_bytes(pkt, pkt->icmp6_h.ns.opt.nonce,
                            pkt->icmp6_h.ns.opt.len);
    }
}

fw_event_details_t icmp6_deserialize(fw_packet_t *pkt)
{
    fw_event_details_t ret = FW_EVENT_DESCR_ALLOW;

    if ((pkt->total_len - pkt->off) < icmp6_min_hdrlen(pkt)) {
        return FW_EVENT_DESCR_ICMP6_HDRLEN_TOO_SMALL;
    }

    fw_pkt_copy_byte(pkt, &pkt->icmp6_h.type);
    fw_pkt_copy_byte(pkt, &pkt->icmp6_h.code);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp6_h.checksum);
    if (pkt->icmp6_h.type == ICMP6_TYPE_ECHO_REQUEST) {
        icmp6_deserialize_echo_req(pkt);
    } else if (pkt->icmp6_h.type == ICMP6_TYPE_ECHO_REPLY) {
        icmp6_deserialize_echo_reply(pkt);
    } else if (pkt->icmp6_h.type == ICMP6_TYPE_NEIGHBOR_SOLICITATION) {
        icmp6_deserialize_neighbor_solicitation(pkt);
    } else {
        ret = FW_EVENT_DESCR_ICMP6_UNSUPPORTED_TYPE;
    }

    return ret;
}
