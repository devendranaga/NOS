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

STATIC uint16_t ieee8021x_mka_get_paramset_len(fw_packet_t *hdr)
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
    bp->paramset_len = ieee8021x_mka_get_paramset_len(hdr);
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

STATIC void ieee8021x_deserialize_peer(fw_packet_t *hdr,
                                       uint32_t paramset_len,
                                       uint8_t *num_peers,
                                       struct ieee8021x_eapol_mka_peer *peer_list)
{
    uint32_t i = 0;
    uint32_t len = 0;

    while (len > paramset_len) {
        (*num_peers) ++;

        fw_pkt_copy_n_bytes(hdr,
                            peer_list[i].mi, sizeof(peer_list[i].mi));
        fw_pkt_copy_4_bytes(hdr, &peer_list[i].mn);
        len += sizeof(peer_list[i].mi) + sizeof(peer_list[i].mn);
        i ++;
    }
}

/* Parse Potential Peer List. */
STATIC fw_event_details_t ieee8021x_deserialize_mka_pp(fw_packet_t *hdr)
{
    struct ieee8021x_eapol_mka_potential_paramset *pp;

    pp = &hdr->dot1x_h.eapol.mka.pp;

    pp->paramset_len =  ieee8021x_mka_get_paramset_len(hdr);
    hdr->off += 2;

    ieee8021x_deserialize_peer(hdr, pp->paramset_len,
                               &pp->num_peers,
                               pp->peer_list);

    return FW_EVENT_DESCR_ALLOW;
}

/* Parse Live Peer List. */
STATIC fw_event_details_t ieee8021x_deserialize_mka_lp(fw_packet_t *hdr)
{
    struct ieee8021x_eapol_mka_live_paramset *lp;

    lp = &hdr->dot1x_h.eapol.mka.lp;

    lp->paramset_len = ieee8021x_mka_get_paramset_len(hdr);
    hdr->off += 2;

    ieee8021x_deserialize_peer(hdr, lp->paramset_len,
                               &lp->num_peers,
                               lp->peer_list);

    return FW_EVENT_DESCR_ALLOW;
}

/* Parse MACsec SAKuse. */
STATIC fw_event_details_t ieee8021x_deserialize_sak_use_paramset(
                                                fw_packet_t *hdr)
{
    struct ieee8021x_eapol_mka_macsec_sak_paramset *mp;

    mp = &hdr->dot1x_h.eapol.mka.mp;

    mp->lan = (hdr->msg[hdr->off] & 0xC0) >> 6;
    mp->ltx = !!(hdr->msg[hdr->off] & 0x20);
    mp->lrx = !!(hdr->msg[hdr->off] & 0x10);
    mp->oan = (hdr->msg[hdr->off] & 0x0C) >> 2;
    mp->otx = !!(hdr->msg[hdr->off] & 0x02);
    mp->orx = !!(hdr->msg[hdr->off] & 0x01);

    hdr->off ++;

    mp->ptx = !!(hdr->msg[hdr->off] & 0x80);
    mp->prx = !!(hdr->msg[hdr->off] & 0x40);
    mp->dp = !!(hdr->msg[hdr->off] & 0x20);

    mp->paramset_len = ieee8021x_mka_get_paramset_len(hdr);
    hdr->off += 2;

    fw_pkt_copy_n_bytes(hdr, mp->latest_mi, sizeof(mp->latest_mi));
    fw_pkt_copy_4_bytes(hdr, &mp->latest_kn);
    fw_pkt_copy_4_bytes(hdr, &mp->latest_lowest_pn);

    fw_pkt_copy_n_bytes(hdr, mp->old_mi, sizeof(mp->old_mi));
    fw_pkt_copy_4_bytes(hdr, &mp->old_kn);
    fw_pkt_copy_4_bytes(hdr, &mp->old_lowest_pn);

    return FW_EVENT_DESCR_ALLOW;
}

/* Parse Dist SAK. */
STATIC fw_event_details_t ieee8021x_deserialize_dist_sak(fw_packet_t *hdr)
{
    struct ieee8021x_eapol_mka_dist_sak_paramset *dp;
    uint32_t wrapped_key_len = 0;

    dp = &hdr->dot1x_h.eapol.mka.dp;

    dp->dist_an = (hdr->msg[hdr->off] & 0xC0) >> 6;
    dp->conf_offset = (hdr->msg[hdr->off] & 0x30) >> 4;

    dp->paramset_len = ieee8021x_mka_get_paramset_len(hdr);
    hdr->off += 2;

    fw_pkt_copy_4_bytes(hdr, &dp->key_number);

    /* AES-GCM-128. */
    if (dp->paramset_len == 28) {
        wrapped_key_len = dp->paramset_len - sizeof(dp->key_number);
        dp->key_wrap_len = wrapped_key_len;
    } else {
        fw_pkt_copy_n_bytes(hdr, dp->cipher, sizeof(dp->cipher));
        wrapped_key_len = dp->paramset_len -
                          sizeof(dp->key_number) -
                          sizeof(dp->cipher);
        dp->key_wrap_len = wrapped_key_len;
    }

    fw_pkt_copy_n_bytes(hdr, dp->key_wrap, dp->key_wrap_len);

    return FW_EVENT_DESCR_ALLOW;
}

/* Parse ICV. */
STATIC fw_event_details_t ieee8021x_deserialize_icv(fw_packet_t *hdr)
{
    struct ieee8021x_eapol_mka_icv_paramset *ip;

    ip = &hdr->dot1x_h.eapol.mka.ip;

    ip->paramset_len = ieee8021x_mka_get_paramset_len(hdr);
    if (ip->paramset_len != MKA_ICV_LEN_MAX) {
        return FW_EVENT_DESCR_8021X_MKA_ICV_LEN_INVAL;
    }

    fw_pkt_copy_n_bytes(hdr, ip->icv, ip->paramset_len);

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

    /* Parse ICV. */
    if ((hdr->total_len - hdr->off) == MKA_ICV_LEN_MAX) {
        fw_pkt_copy_n_bytes(hdr,
                            hdr->dot1x_h.eapol.mka.ip.icv, MKA_ICV_LEN_MAX);
    }

    while (hdr->off > hdr->total_len) {
        switch (hdr->msg[hdr->off]) {
            case MKA_LIVE_PEERLIST_PARAMSET: {
                hdr->off ++;

                evt_descr = ieee8021x_deserialize_mka_lp(hdr);
                if (evt_descr != FW_EVENT_DESCR_ALLOW) {
                    return evt_descr;
                }
            } break;
            case MKA_POTENTIAL_PEERLIST_PARAMSET: {
                hdr->off ++;

                /* Deserialize Potential Peer List. */
                evt_descr = ieee8021x_deserialize_mka_pp(hdr);
                if (evt_descr != FW_EVENT_DESCR_ALLOW) {
                    return evt_descr;
                }
            } break;
            case MKA_MACSEC_SAKUSE_PARAMSET: {
                hdr->off ++;

                evt_descr = ieee8021x_deserialize_sak_use_paramset(hdr);
                if (evt_descr != FW_EVENT_DESCR_ALLOW) {
                    return evt_descr;
                }
            } break;
            case MKA_DIST_SAK_PARAMSET: {
                hdr->off ++;

                evt_descr = ieee8021x_deserialize_dist_sak(hdr);
                if (evt_descr != FW_EVENT_DESCR_ALLOW) {
                    return evt_descr;
                }
            } break;
            case MKA_ICV_PARAMSET: {
                hdr->off ++;

                evt_descr = ieee8021x_deserialize_icv(hdr);
                if (evt_descr != FW_EVENT_DESCR_ALLOW) {
                    return evt_descr;
                }
            } break;
            default: {
                return FW_EVENT_DESCR_8021X_MKA_INVAL_PARAMSET_TYPE;
            } break;
        }
    }

    return evt_descr;
}

fw_event_details_t ieee8021x_deserialize(fw_packet_t *hdr)
{
    return ieee8021x_deserialize_eapol(hdr);
}

