#include <protocol_generic.h>
#include <fw_pkt.h>
#include <arp.h>

fw_event_details_t arp_deserialize(fw_packet_t *hdr)
{
    fw_event_details_t type = FW_EVENT_DESCR_ALLOW;

    fw_copy_2_bytes(hdr, &hdr->arp_h.hwtype);
    fw_copy_2_bytes(hdr, &hdr->arp_h.proto_type);
    fw_copy_byte(hdr, &hdr->arp_h.hw_addr_len);
    fw_copy_byte(hdr, &hdr->arp_h.proto_addr_len);
    fw_copy_2_bytes(hdr, &hdr->arp_h.operation);
    fw_copy_macaddr(hdr, hdr->arp_h.sender_hw_addr);
    fw_copy_4_bytes(hdr, &hdr->arp_h.sender_proto_addr);
    fw_copy_macaddr(hdr, hdr->arp_h.target_hw_addr);
    fw_copy_4_bytes(hdr, &hdr->arp_h.target_proto_addr);

    return type;
}

