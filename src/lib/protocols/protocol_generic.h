/**
 * @brief - Implements Protocol Generic header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_GENERIC_H__
#define __LIB_PROTOCOLS_GENERIC_H__

#include <event_def.h>
#include <fw_pkt.h>

enum fw_protocol_type {
    FW_PROTO_ARP,
};

typedef enum fw_protocol_type fw_protocol_type_t;

/**
 * @brief - copy mac address.
 *
 * @param [in] pkt : packet pointer.
 * @param [in] mac : MAC address.
 */
void fw_copy_macaddr(fw_packet_t *pkt, uint8_t *mac);
void fw_copy_2_bytes(fw_packet_t *pkt, uint16_t *val);
void fw_copy_byte(fw_packet_t *pkt, uint8_t *val);
void fw_copy_4_bytes(fw_packet_t *pkt, uint32_t *val);
bool fw_has_bit_set(fw_packet_t *pkt, uint32_t pos);

fw_event_details_t ethernet_deserialize(fw_packet_t *hdr);
fw_event_details_t arp_deserialize(fw_packet_t *hdr);
fw_event_details_t vlan_deserialize(fw_packet_t *hdr);
fw_event_details_t ipv4_deserialize(fw_packet_t *hdr);

fw_event_details_t parse_protocol(struct fw_packet *pkt);

#endif

