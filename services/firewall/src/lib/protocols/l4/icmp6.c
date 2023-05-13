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

STATIC void icmp6_deserialize_router_solicitation(fw_packet_t *pkt)
{
    fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.rs.reserved);
}

STATIC fw_event_details_t
icmp6_deserialize_router_advertisement(fw_packet_t *pkt)
{
    uint8_t flags = 0;

    fw_pkt_copy_byte(pkt, &pkt->icmp6_h.ra.cur_hop_limit);
    fw_pkt_copy_byte(pkt, &flags);
    pkt->icmp6_h.ra.flags_managed_addr_config = !!(flags & 0x80);
    pkt->icmp6_h.ra.flags_other_config = !!(flags & 0x40);
    pkt->icmp6_h.ra.flags_home_agent = !!(flags & 0x20);
    pkt->icmp6_h.ra.flags_prf = (flags & 18) >> 3;
    pkt->icmp6_h.ra.flags_proxy = !!(flags & 0x04);
    pkt->icmp6_h.ra.flags_reserved = !!(flags & 0x02);
    fw_pkt_copy_2_bytes(pkt, &pkt->icmp6_h.ra.router_lifetime);
    fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.ra.reachable_time);
    fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.ra.retransmission_timer);

    pkt->icmp6_h.ra.opt_flags = 0;

    while ((pkt->total_len - pkt->off) > 0) {
        switch (pkt->msg[pkt->off]) {
            case ICMP6_OPT_TYPE_SOURCE_LLADDR: {
                pkt->icmp6_h.ra.opt_flags |= ICMP6_OPT_FLAGS_SOURCE_LLADDR;
                pkt->off ++;

                fw_pkt_copy_byte(pkt, &pkt->icmp6_h.ra.opt_source_ll.len);
                if (pkt->icmp6_h.ra.opt_source_ll.len != 1) {
                    return FW_EVENT_DESCR_ICMP6_RA_OPT_SOURCE_LLADDR_LEN_INVAL;
                }
                pkt->icmp6_h.ra.opt_source_ll.len *= 8;

                fw_pkt_copy_6_bytes(pkt, pkt->icmp6_h.ra.opt_source_ll.lladdr);
            } break;
            case ICMP6_OPT_TYPE_MTU: {
                pkt->icmp6_h.ra.opt_flags |= ICMP6_OPT_FLAGS_MTU;
                pkt->off ++;

                fw_pkt_copy_byte(pkt, &pkt->icmp6_h.ra.opt_mtu.len);
                if (pkt->icmp6_h.ra.opt_mtu.len != 1) {
                    return FW_EVENT_DESCR_ICMP6_RA_OPT_MTU_LEN_INVAL;
                }
                pkt->icmp6_h.ra.opt_mtu.len *= 8;

                fw_pkt_copy_2_bytes(pkt, &pkt->icmp6_h.ra.opt_mtu.reserved);
                fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.ra.opt_mtu.mtu);
            } break;
            case ICMP6_OPT_TYPE_PREFIX_INFO: {
                pkt->icmp6_h.ra.opt_flags |= ICMP6_OPT_FLAGS_PREFIX_INFO;
                pkt->off ++;

                fw_pkt_copy_byte(pkt, &pkt->icmp6_h.ra.opt_prefix_info.len);
                if (pkt->icmp6_h.ra.opt_prefix_info.len != 4) {
                    return FW_EVENT_DESCR_ICMP6_RA_OPT_PREFIX_INFO_LEN_INVAL;
                }
                pkt->icmp6_h.ra.opt_prefix_info.len *= 8;

                fw_pkt_copy_byte(pkt, &pkt->icmp6_h.ra.opt_prefix_info.prefix_len);

                fw_pkt_copy_byte(pkt, &flags);
                pkt->icmp6_h.ra.opt_prefix_info.flags_onlink = 0;
                pkt->icmp6_h.ra.opt_prefix_info.flags_autonomous_addr = 0;
                pkt->icmp6_h.ra.opt_prefix_info.flags_router_addr = 0;

                if (!!(flags & 0x80)) {
                    pkt->icmp6_h.ra.opt_prefix_info.flags_onlink = 1;
                }
                if (!!(flags & 0x40)) {
                    pkt->icmp6_h.ra.opt_prefix_info.flags_autonomous_addr = 1;
                }
                if (!!(flags & 0x20)) {
                    pkt->icmp6_h.ra.opt_prefix_info.flags_router_addr = 1;
                }

                fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.ra.opt_prefix_info.valid_lifetime);
                fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.ra.opt_prefix_info.preferred_lifetime);
                fw_pkt_copy_4_bytes(pkt, &pkt->icmp6_h.ra.opt_prefix_info.reserved);
                fw_pkt_copy_16_bytes(pkt, pkt->icmp6_h.ra.opt_prefix_info.prefix);
            } break;
            default:
                return FW_EVENT_DESCR_ICMP6_OPT_UNSUPPORTED;
        }
    }

    return FW_EVENT_DESCR_ALLOW;
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
    } else if (pkt->icmp6_h.type == ICMP6_TYPE_ROUTER_SOLICITATION) {
        icmp6_deserialize_router_solicitation(pkt);
    } else if (pkt->icmp6_h.type == ICMP6_TYPE_ROUTER_ADVERTISEMENT) {
        ret = icmp6_deserialize_router_advertisement(pkt);
    } else {
        ret = FW_EVENT_DESCR_ICMP6_UNSUPPORTED_TYPE;
    }

    return ret;
}

