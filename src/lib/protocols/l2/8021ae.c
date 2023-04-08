/**
 * @brief - Implements 802.1AE parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>
#include <debug.h>

#ifdef ENABLE_PROTOCOL_PRINTS
void ieee8021ae_print(ieee8021ae_hdr_t *hdr)
{
    uint32_t i;

    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "IEEE 802.1AE: {\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t SecTAG: 0x%02x\n", hdr->sectag);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t ver: %d\n", hdr->ver);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t es: %d\n", hdr->es);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t sc: %d\n", hdr->sc);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t scb: %d\n", hdr->scb);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t e: %d\n", hdr->e);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t c: %d\n", hdr->c);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t an: %d\n", hdr->an);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t short_len: %d\n", hdr->short_len);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t packet_no: %d\n", hdr->packet_no);
    if (hdr->sc) {
        fw_debug(FW_DEBUG_LEVEL_VERBOSE,
                 "\t SCI: [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                 hdr->sci[0], hdr->sci[1],
                 hdr->sci[2], hdr->sci[3],
                 hdr->sci[4], hdr->sci[5]);
    }
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t port_id: %d\n", hdr->port_id);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t packet_len: %d\n", hdr->pkt_len);
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t ICV: {\n\t ");
    for (i = 0; i < IEEE8021AE_ICV_LEN; i ++) {
        fprintf(stderr, "%02x ", hdr->icv[i]);
    }
    fprintf(stderr, "\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "\t }\n");
    fw_debug(FW_DEBUG_LEVEL_VERBOSE, "}\n");
}
#endif

bool ieee8021ae_has_encrypt_on(ieee8021ae_hdr_t *hdr)
{
    return ((hdr->e == true) && (hdr->c == true));
}

fw_event_details_t ieee8021ae_deserialize(fw_packet_t *pkt)
{
    fw_pkt_copy_byte(pkt, &pkt->macsec_h.sectag);

    pkt->macsec_h.ver = !!(pkt->macsec_h.sectag & 0x80);
    pkt->macsec_h.es = !!(pkt->macsec_h.sectag & 0x40);
    pkt->macsec_h.sc = !!(pkt->macsec_h.sectag & 0x20);
    pkt->macsec_h.scb = !!(pkt->macsec_h.sectag & 0x10);
    pkt->macsec_h.e = !!(pkt->macsec_h.sectag & 0x08);
    pkt->macsec_h.c = !!(pkt->macsec_h.sectag & 0x04);
    pkt->macsec_h.an = (pkt->macsec_h.sectag & 0x03);

    fw_pkt_copy_byte(pkt, &pkt->macsec_h.short_len);
    fw_pkt_copy_4_bytes(pkt, &pkt->macsec_h.packet_no);
    if (pkt->macsec_h.sc) {
        fw_pkt_copy_6_bytes(pkt, pkt->macsec_h.sci);
    }
    fw_pkt_copy_2_bytes(pkt, &pkt->macsec_h.port_id);

    memcpy(pkt->macsec_h.icv,
           pkt->msg + pkt->total_len - IEEE8021AE_ICV_LEN, IEEE8021AE_ICV_LEN);
    pkt->macsec_h.pkt_len = pkt->total_len - pkt->off - IEEE8021AE_ICV_LEN;

    ieee8021ae_print(&pkt->macsec_h);

    return FW_EVENT_DESCR_ALLOW;    
}

