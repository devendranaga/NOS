#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>
#include <debug.h>

fw_event_details_t udp_deserialize(fw_packet_t *pkt)
{
    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.src_port);
    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.dst_port);
    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.length);
    fw_pkt_copy_2_bytes(pkt, &pkt->udp_h.checksum);

    return FW_EVENT_DESCR_ALLOW;
}

