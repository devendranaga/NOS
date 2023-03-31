/**
 * @brief - Implements ARP parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <firewall_common.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <arp.h>

STATIC INLINE bool arp_op_in_range(uint16_t operation)
{
    if ((operation < ARP_OP_ARP_REQ) ||
        (operation > ARP_OP_INARP_REPLY)) {
        return false;
    }

    return true;
}

/* Check ARP Hardware Type in range. */
STATIC INLINE bool arp_hwtype_in_range(uint16_t hwtype)
{
    if ((hwtype < ARP_HW_TYPE_ETHERNET) ||
        (hwtype > ARP_HW_TYPE_SERIAL)) {
        return false;
    }

    return true;
}

/* Get ARP Header length. */
STATIC INLINE uint8_t arp_get_hdr_len(arp_header_t *arp_h)
{
    return sizeof(arp_h->hwtype) +
           sizeof(arp_h->proto_type) +
           sizeof(arp_h->hw_addr_len) +
           sizeof(arp_h->proto_addr_len) +
           sizeof(arp_h->operation) +
           sizeof(arp_h->sender_hw_addr) +
           sizeof(arp_h->sender_proto_addr) +
           sizeof(arp_h->target_hw_addr) +
           sizeof(arp_h->target_proto_addr);
}

fw_event_details_t arp_deserialize(fw_packet_t *hdr)
{
    uint16_t arp_hdr_len = 0;

    /* Get header length and check if its too small. */
    arp_hdr_len = arp_get_hdr_len(&hdr->arp_h);
    if (arp_hdr_len < hdr->total_len) {
        return FW_EVENT_DESCR_ARP_HDR_LEN_TOO_SHORT;
    }

    /* Check Hardware type within range. */
    fw_copy_2_bytes(hdr, &hdr->arp_h.hwtype);
    if (!arp_hwtype_in_range(hdr->arp_h.hwtype)) {
        return FW_EVENT_DESCR_ARP_HWTYPE_INVAL;
    }

    fw_copy_2_bytes(hdr, &hdr->arp_h.proto_type);
    fw_copy_byte(hdr, &hdr->arp_h.hw_addr_len);

    /* ARP Hardware Addr length is not 6. */
    if (hdr->arp_h.hw_addr_len != ARP_HW_ADDR_LEN) {
        return FW_EVENT_DESCR_ARP_INVAL_HWADDR_LEN;
    }

    fw_copy_byte(hdr, &hdr->arp_h.proto_addr_len);

    /* ARP Protocol addr length is not 4. */
    if (hdr->arp_h.proto_type != ARP_PROTO_ADDR_LEN) {
        return FW_EVENT_DESCR_ARP_INVAL_PROTO_ADDR_LEN;
    }

    fw_copy_2_bytes(hdr, &hdr->arp_h.operation);

    /* Check ARP operation is within range. */
    if (!arp_op_in_range(hdr->arp_h.operation)) {
        return FW_EVENT_DESCR_ARP_OP_INVAL;
    }

    fw_copy_macaddr(hdr, hdr->arp_h.sender_hw_addr);
    fw_copy_4_bytes(hdr, &hdr->arp_h.sender_proto_addr);
    fw_copy_macaddr(hdr, hdr->arp_h.target_hw_addr);
    fw_copy_4_bytes(hdr, &hdr->arp_h.target_proto_addr);

    return FW_EVENT_DESCR_ALLOW;
}

