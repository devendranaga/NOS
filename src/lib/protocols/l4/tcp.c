/**
 * @brief - Implements TCP parsing.
 * 
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>
#include <debug.h>

#define CWR_BIT 7
#define ECE_BIT 6
#define URG_BIT 5
#define ACK_BIT 4
#define PSH_BIT 3
#define RST_BIT 2
#define SYN_BIT 1
#define FIN_BIT 0

#ifdef ENABLE_PROTOCOL_PRINTS
void tcp_print(tcp_header_t *tcp_h)
{
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "tcp: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t src_port: %d\n", tcp_h->src_port);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t dst_port: %d\n", tcp_h->dst_port);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t seq_no: %d\n", tcp_h->seq_no);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t ack_no: %d\n", tcp_h->ack_no);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t data_offset: %d\n", tcp_h->data_offset);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t reserved: %d\n", tcp_h->reserved);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t flags: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t cwr: %s\n", tcp_h->cwr ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t ece: %s\n", tcp_h->ece ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t urg: %s\n", tcp_h->urg ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t ack: %s\n", tcp_h->ack ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t psh: %s\n", tcp_h->psh ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t rst: %s\n", tcp_h->rst ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t syn: %s\n", tcp_h->syn ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t\t fin: %s\n", tcp_h->fin ? "True": "False");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t }\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t win_size: %d\n", tcp_h->win_size);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t checksum: %d\n", tcp_h->checksum);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t urg_pointer: %d\n", tcp_h->urg_pointer);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "}\n");
}
#endif

fw_event_details_t tcp_deserialize(fw_packet_t *pkt)
{
    fw_pkt_copy_2_bytes(pkt, &pkt->tcp_h.src_port);
    if (pkt->tcp_h.src_port == 0) {
        return FW_EVENT_DESCR_TCP_SRC_PORT_ZERO;
    }

    fw_pkt_copy_2_bytes(pkt, &pkt->tcp_h.dst_port);
    if (pkt->tcp_h.dst_port == 0) {
        return FW_EVENT_DESCR_TCP_DST_PORT_ZERO;
    }

    fw_pkt_copy_4_bytes(pkt, &pkt->tcp_h.seq_no);
    fw_pkt_copy_4_bytes(pkt, &pkt->tcp_h.ack_no);

    pkt->tcp_h.data_offset = (pkt->msg[pkt->off] & 0xF0) >> 4;
    pkt->tcp_h.reserved = (pkt->msg[pkt->off] & 0x0F);
    if (pkt->tcp_h.reserved == 0) {
        return FW_EVENT_DESCR_TCP_RESERVED_FLAGS_SET;
    }
    pkt->off ++;

    pkt->tcp_h.flags = pkt->msg[pkt->off];
    if (pkt->tcp_h.flags == 0) {
        return FW_EVENT_DESCR_TCP_HDR_FLAGS_NULL;
    }

    pkt->tcp_h.cwr = fw_pkt_has_bit_set(pkt, CWR_BIT);
    pkt->tcp_h.ece = fw_pkt_has_bit_set(pkt, ECE_BIT);
    pkt->tcp_h.urg = fw_pkt_has_bit_set(pkt, URG_BIT);
    pkt->tcp_h.ack = fw_pkt_has_bit_set(pkt, ACK_BIT);
    pkt->tcp_h.psh = fw_pkt_has_bit_set(pkt, PSH_BIT);
    pkt->tcp_h.rst = fw_pkt_has_bit_set(pkt, RST_BIT);
    pkt->tcp_h.syn = fw_pkt_has_bit_set(pkt, SYN_BIT);
    pkt->tcp_h.fin = fw_pkt_has_bit_set(pkt, FIN_BIT);

    pkt->off ++;

    fw_pkt_copy_2_bytes(pkt, &pkt->tcp_h.win_size);
    fw_pkt_copy_2_bytes(pkt, &pkt->tcp_h.checksum);
    fw_pkt_copy_2_bytes(pkt, &pkt->tcp_h.urg_pointer);

    tcp_print(&pkt->tcp_h);

    return FW_EVENT_DESCR_ALLOW;
}
