/**
 * @brief - Implement DHCP header parsing.
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
#include <ntp_v4.h>

fw_event_details_t ntp_v4_deserialize(fw_packet_t *hdr)
{
    ntpv4_header_t *ntpv4_h = &hdr->ntpv4_h;

    ntpv4_h->leap_indicator = (hdr->msg[hdr->off] & 0xC0) >> 6;
    ntpv4_h->version_number = (hdr->msg[hdr->off] & 0x38) >> 3;
    ntpv4_h->mode = (hdr->msg[hdr->off] & 0x07);

    fw_pkt_copy_byte(hdr, &ntpv4_h->peer_clock_stratum);
    fw_pkt_copy_byte(hdr, &ntpv4_h->peer_polling_interval);
    fw_pkt_copy_byte(hdr, &ntpv4_h->peer_clock_precision);
    fw_pkt_copy_4_bytes(hdr, &ntpv4_h->root_delay_sec);
    fw_pkt_copy_4_bytes(hdr, &ntpv4_h->root_dispersion_sec);
    fw_pkt_copy_8_bytes_u64(hdr, &ntpv4_h->reference_timestamp);
    fw_pkt_copy_8_bytes_u64(hdr, &ntpv4_h->origin_timestamp);
    fw_pkt_copy_8_bytes_u64(hdr, &ntpv4_h->receive_timestamp);
    fw_pkt_copy_8_bytes_u64(hdr, &ntpv4_h->transmit_timestamp);
    fw_pkt_copy_4_bytes(hdr, &ntpv4_h->key_id);
    fw_pkt_copy_n_bytes(hdr, ntpv4_h->mac, sizeof(ntpv4_h->mac));

    return FW_EVENT_DESCR_ALLOW;
}

