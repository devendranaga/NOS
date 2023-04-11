#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>
#include <debug.h>

fw_event_details_t udp_deserialize(fw_packet_t *pkt)
{
    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.src_port);
    if (pkt->udp_h.src_port == 0) {
        return FW_EVENT_DESCR_UDP_SRC_PORT_ZERO;
    }

    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.dst_port);
    if (pkt->udp_h.dst_port == 0) {
        return FW_EVENT_DESCR_UDP_DST_PORT_ZERO;
    }

    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.length);
    if (pkt->udp_h.length == 0) {
        return FW_EVENT_DESCR_UDP_PAYLOAD_LEN_ZERO;
    }

    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.checksum);

    return FW_EVENT_DESCR_ALLOW;
}

