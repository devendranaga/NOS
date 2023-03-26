/**
 * @brief - Implements Ethernet Header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_ETHERNET_H__
#define __LIB_PROTOCOLS_ETHERNET_H__

#define FW_ETHERTYPE_ARP  0x0806
#define FW_ETHERTYPE_IPV4 0x0800
#define FW_MACADDR_LEN    6

struct ethernet_header {
    uint8_t src[FW_MACADDR_LEN];
    uint8_t dst[FW_MACADDR_LEN];
    uint16_t ethertype;
};

#endif

