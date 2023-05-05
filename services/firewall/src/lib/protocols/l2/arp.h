/**
 * @brief - Implement ARP header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FW_PROTOCOLS_ARP_H__
#define __FW_PROTOCOLS_ARP_H__

/**
 * @brief - defined ARP header
 */
struct arp_header {
#define ARP_HW_TYPE_ETHERNET        1
#define ARP_HW_TYPE_IEEE_802        6
#define ARP_HW_TYPE_ARCNET          7
#define ARP_HW_TYPE_FRAME_RELAY     15
#define ARP_HW_TYPE_ATM             16
#define ARP_HW_TYPE_HDLC            17
#define ARP_HW_TYPE_FIBRE_CHAN      18
#define ARP_HW_TYPE_ATM2            19
#define ARP_HW_TYPE_SERIAL          20
    /* hardware type */
    uint16_t hwtype;

    /* ethertype */
    uint16_t proto_type;
#define ARP_HW_ADDR_LEN 6
    /* 6 bytes of mac address */
    uint8_t hw_addr_len;
#define ARP_PROTO_ADDR_LEN 4
    /* 4 bytes of protocol len */
    uint8_t proto_addr_len;
#define ARP_OP_ARP_REQ              1
#define ARP_OP_ARP_REPLY            2
#define ARP_OP_RARP_REQ             3
#define ARP_OP_RARP_REPLY           4
#define ARP_OP_DRARP_REQ            5
#define ARP_OP_DRARP_REPLY          6
#define ARP_OP_DRARP_ERROR          7
#define ARP_OP_INARP_REQ            8
#define ARP_OP_INARP_REPLY          9
    /* type of ARP request packet */
    uint16_t operation;
    /* sender's mac */
    uint8_t sender_hw_addr[6];
    /* sender's ipaddress */
    uint32_t sender_proto_addr;
    /* target's mac */
    uint8_t target_hw_addr[6];
    /* target's ipaddress */
    uint32_t target_proto_addr;
};

typedef struct arp_header arp_header_t;

#endif

