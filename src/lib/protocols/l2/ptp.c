/**
 * @brief - Implements PTP header parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <stdint.h>
#include <events.h>
#include <fw_pkt.h>
#include <protocol_generic.h>

#define PTP_MSG_TYPE_SYNC               0x00
#define PTP_MSG_TYPE_PEER_DELAY_REQ     0x02
#define PTP_MSG_TYPE_ANNOUNCE           0x0B

bool ptp_msg_type_is_sync(ptp_header_t *ptp_hdr)
{
    return ptp_hdr->message_type == PTP_MSG_TYPE_SYNC;
}

bool ptp_msg_type_is_peer_delay_req(ptp_header_t *ptp_hdr)
{
    return ptp_hdr->message_type == PTP_MSG_TYPE_PEER_DELAY_REQ;
}

bool ptp_msg_type_is_announce(ptp_header_t *ptp_hdr)
{
    return ptp_hdr->message_type == PTP_MSG_TYPE_ANNOUNCE;
}

fw_event_details_t ptp_deserialize(fw_packet_t *pkt)
{
    pkt->ptp_h.major_sdoid = (pkt->msg[pkt->off] & 0xF0) >> 4;
    pkt->ptp_h.message_type = (pkt->msg[pkt->off] & 0x0F);
    pkt->off ++;

    pkt->ptp_h.minor_ptp_version = (pkt->msg[pkt->off] & 0xF0) >> 4;
    pkt->ptp_h.version_ptp = (pkt->msg[pkt->off] & 0x0F);
    pkt->off ++;

    fw_pkt_copy_2_bytes(pkt, &pkt->ptp_h.message_len);
    fw_pkt_copy_byte(pkt, &pkt->ptp_h.domain_no);
    fw_pkt_copy_byte(pkt, &pkt->ptp_h.minor_sdoid);
    fw_pkt_copy_2_bytes(pkt, &pkt->ptp_h.flags);

    fw_pkt_copy_6_bytes_u64(pkt, &pkt->ptp_h.corrections_ns);
    fw_pkt_copy_2_bytes(pkt, &pkt->ptp_h.corrections_sub_ns);

    fw_pkt_copy_4_bytes(pkt, &pkt->ptp_h.message_type_specific);
    fw_pkt_copy_8_bytes(pkt, pkt->ptp_h.clk_id);
    fw_pkt_copy_2_bytes(pkt, &pkt->ptp_h.source_port_id);
    fw_pkt_copy_2_bytes(pkt, &pkt->ptp_h.seq_id);
    fw_pkt_copy_byte(pkt, &pkt->ptp_h.control_field);
    fw_pkt_copy_byte(pkt, &pkt->ptp_h.log_message_period);
    fw_pkt_copy_6_bytes_u64(pkt, &pkt->ptp_h.origin_timestamp_sec);
    fw_pkt_copy_4_bytes(pkt, &pkt->ptp_h.origin_timestamp_ns);

    /* Parse Announce Header. */
    if (pkt->ptp_h.message_type == PTP_MSG_TYPE_ANNOUNCE) {
        fw_pkt_copy_2_bytes(pkt,
                    &pkt->ptp_h.announce_hdr.origin_current_utc_offset);
        pkt->off ++;
        fw_pkt_copy_byte(pkt,
                    &pkt->ptp_h.announce_hdr.priority_1);
        fw_pkt_copy_byte(pkt,
                    &pkt->ptp_h.announce_hdr.grand_master_clock_class);
        fw_pkt_copy_byte(pkt,
                    &pkt->ptp_h.announce_hdr.grand_master_clock_accuracy);
        fw_pkt_copy_2_bytes(pkt,
                    &pkt->ptp_h.announce_hdr.grand_master_clock_variance);
        fw_pkt_copy_byte(pkt,
                    &pkt->ptp_h.announce_hdr.priority_2);
        fw_pkt_copy_8_bytes(pkt,
                    pkt->ptp_h.announce_hdr.grand_master_clock_id);
        fw_pkt_copy_2_bytes(pkt,
                    &pkt->ptp_h.announce_hdr.local_steps_removed);
        fw_pkt_copy_byte(pkt,
                    &pkt->ptp_h.announce_hdr.timesource);
    }

    pkt->is_layer2_ptp = true;

    return FW_EVENT_DESCR_ALLOW;
}

