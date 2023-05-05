#include <firewall_common.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <debug.h>
#include <stdio.h>

fw_event_details_t someip_deserialize(fw_packet_t *hdr)
{
    someip_header_t *someip_h = &hdr->someip_h;

    fw_pkt_copy_2_bytes(hdr, &someip_h->service_id);
    fw_pkt_copy_2_bytes(hdr, &someip_h->method_id);
    fw_pkt_copy_4_bytes(hdr, &someip_h->length);
    fw_pkt_copy_2_bytes(hdr, &someip_h->client_id);
    fw_pkt_copy_2_bytes(hdr, &someip_h->session_id);
    fw_pkt_copy_byte(hdr, &someip_h->version);
    fw_pkt_copy_byte(hdr, &someip_h->interface_version);
    fw_pkt_copy_byte(hdr, &someip_h->message_type);
    fw_pkt_copy_byte(hdr, &someip_h->return_code);

    return FW_EVENT_DESCR_ALLOW;
}
