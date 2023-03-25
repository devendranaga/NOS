#ifndef __LIB_PROTOCOLS_GENERIC_H__
#define __LIB_PROTOCOLS_GENERIC_H__

#include <event_def.h>
#include <fw_pkt.h>

enum fw_protocol_type {
    FW_PROTO_ARP,
};

typedef enum fw_protocol_type fw_protocol_type_t;

void fw_copy_macaddr(fw_packet_t *pkt, uint8_t *mac);
void fw_copy_2_bytes(fw_packet_t *pkt, uint16_t *val);

fw_event_type_t ethernet_deserialize(fw_packet_t *hdr);
fw_event_type_t arp_deserialize(fw_packet_t *hdr);
fw_event_type_t ipv4_deserialize(fw_packet_t *hdr);

fw_event_type_t parse_protocol(struct fw_packet *pkt);

#endif

