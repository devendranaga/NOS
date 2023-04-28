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
void fw_pkt_copy_macaddr(fw_packet_t *pkt, uint8_t *mac);
void fw_pkt_encode_macaddr(fw_packet_t *pkt, uint8_t *mac);

void fw_pkt_copy_2_bytes(fw_packet_t *pkt, uint16_t *val);
void fw_pkt_encode_2_bytes(fw_packet_t *pkt, uint16_t val);

void fw_pkt_copy_byte(fw_packet_t *pkt, uint8_t *val);
void fw_pkt_encode_byte(fw_packet_t *pkt, uint8_t val);

void fw_pkt_copy_4_bytes(fw_packet_t *pkt, uint32_t *val);
void fw_pkt_encode_4_bytes(fw_packet_t *pkt, uint32_t val);

bool fw_pkt_has_bit_set(fw_packet_t *pkt, uint32_t pos);
void fw_pkt_set_bit(fw_packet_t *pkt, uint32_t pos);

void fw_pkt_copy_6_bytes(fw_packet_t *pkt, uint8_t *val);
void fw_pkt_copy_6_bytes_u64(fw_packet_t *pkt, uint64_t *val);
void fw_pkt_copy_8_bytes(fw_packet_t *pkt, uint8_t *val);
void fw_pkt_copy_16_bytes(fw_packet_t *pkt, uint8_t *val);
void fw_pkt_copy_n_bytes(fw_packet_t *pkt, uint8_t *val, uint32_t bytes);

fw_event_details_t ethernet_deserialize(fw_packet_t *hdr);
fw_event_details_t ethernet_serialize(fw_packet_t *hdr);
fw_event_details_t arp_deserialize(fw_packet_t *hdr);
fw_event_details_t arp_serialize(fw_packet_t *hdr);
fw_event_details_t vlan_deserialize(fw_packet_t *hdr);
fw_event_details_t ieee8021ae_deserialize(fw_packet_t *pkt);
fw_event_details_t ipv4_deserialize(fw_packet_t *hdr);
fw_event_details_t dhcp_deserialize(fw_packet_t *hdr);
void dhcp_free(fw_packet_t *hdr);

/**
 * @brief - Validate IPv4 checksum.
 *
 * @param[in] hdr - Received packet.
 *
 * @return true if checksum validation is success. false
 * if checksum validation fails.
 */
bool ipv4_pkt_validate_checksum(fw_packet_t *hdr);
fw_event_details_t ipv6_deserialize(fw_packet_t *pkt);
fw_event_details_t ptp_deserialize(fw_packet_t *hdr);
fw_event_details_t icmp_deserialize(fw_packet_t *hdr);
fw_event_details_t udp_deserialize(fw_packet_t *hdr);
fw_event_details_t tcp_deserialize(fw_packet_t *pkt);

fw_event_details_t parse_protocol(struct fw_packet *pkt);

#endif

