#include <firewall_common.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <8021x.h>
#include <debug.h>
#include <stdio.h>

STATIC bool ieee8021x_mka_version_in_range(uint8_t version)
{
    if ((version < MKA_VERSION_1) || (version > MKA_VERSION_3)) {
        return false;
    }

    return true;
}

STATIC uint16_t get_paramset_len(fw_packet_t *hdr)
{
    return ((hdr->msg[hdr->off] & 0x0F) |
            (hdr->msg[hdr->off + 1]));
}

STATIC INLINE void ieee8021x_get_sci(fw_packet_t *hdr, uint8_t *sci)
{
    fw_pkt_copy_8_bytes(hdr, sci);
}

STATIC INLINE void ieee8021x_get_mi(fw_packet_t *hdr, uint8_t *mi)
{
    fw_pkt_copy_n_bytes(hdr, mi, MKA_MI_LEN);
}

/**
 * @brif Parse Basic PArameter set.
 */
STATIC fw_event_details_t ieee8021x_deserialize_mka_bp(fw_packet_t *hdr)
{
    struct ieee8021x_eapol_mka_basic_paramset *bp;

    bp = &hdr->dot1x_h.eapol.mka.bp;

    fw_pkt_copy_byte(hdr, &bp->version);
    if (ieee8021x_mka_version_in_range(bp->version)) {
        return FW_EVENT_DESCR_8021X_MKA_VERSION_OUT_OF_RANGE;
    }

    fw_pkt_copy_byte(hdr, &bp->key_server_priority);
    bp->key_server = !!(hdr->msg[hdr->off] & 0x80);
    bp->macsec_desired = !!(hdr->msg[hdr->off] & 0x40);
    bp->macsec_capability = (hdr->msg[hdr->off] & 0x30) >> 4;
    bp->paramset_len = get_paramset_len(hdr);
    hdr->off += 2;

    ieee8021x_get_sci(hdr, bp->sci);
    ieee8021x_get_mi(hdr, bp->actor_mi);
    fw_pkt_copy_4_bytes(hdr, &bp->actor_mn);
    fw_pkt_copy_4_bytes(hdr, &bp->alg_agility);

    if (bp->alg_agility != MKA_ALGORITHM_AGILITY) {
        return FW_EVENT_DESCR_8021X_MKA_ALG_AGILITY_INVALID;
    }

    bp->ckn_len = bp->paramset_len - MKA_BPS_LEN;
    if (bp->ckn_len > MKA_BPS_LEN) {
        return FW_EVENT_DESCR_8021X_MKA_CKN_TOO_LARGE;
    }
    fw_pkt_copy_n_bytes(hdr, bp->ckn, bp->ckn_len);

    return FW_EVENT_DESCR_ALLOW;
}

STATIC fw_event_details_t ieee8021x_deserialize_eapol(fw_packet_t *hdr)
{
    fw_event_details_t evt_descr;

    fw_pkt_copy_byte(hdr, &hdr->dot1x_h.eapol.version);
    fw_pkt_copy_byte(hdr, &hdr->dot1x_h.eapol.type);
    fw_pkt_copy_2_bytes(hdr, &hdr->dot1x_h.eapol.length);

    evt_descr = ieee8021x_deserialize_mka_bp(hdr);
    hdr->dot1x_h.eapol.mka.paramset_preset |= MKA_BASIC_PARAMSET_BIT;

    return evt_descr;
}

fw_event_details_t ieee8021x_deserialize(fw_packet_t *hdr)
{
    return ieee8021x_deserialize_eapol(hdr);
}

