/**
 * @brief - Implements Ethernet Header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_ETHERNET_H__
#define __LIB_PROTOCOLS_ETHERNET_H__

#define FW_ETHERTYPE_ARP                0x0806
#define FW_ETHERTYPE_IPV4               0x0800
#define FW_ETHERTYPE_SRP                0x22EA
#define FW_ETHERTYPE_VLAN               0x8100
#define FW_ETHERTYPE_IPV6               0x86DD
#define FW_ETHERTYPE_MPLS_UNICAST       0x8847
#define FW_ETHERTYPE_MPLS_MULTICAST     0x8848
#define FW_ETHERTYPE_PPPOE_DISCOVERY    0x8863
#define FW_ETHERTYPE_PPPPE_SESS_STAGE   0x8864
#define FW_ETHERTYPE_EAPOL_MKA          0x888E
#define FW_ETHERTYPE_MACSEC             0x88E5
#define FW_ETHERTYPE_PTP                0x88F7

#define FW_MACADDR_LEN                  6

struct ethernet_header {
    uint8_t src[FW_MACADDR_LEN];
    uint8_t dst[FW_MACADDR_LEN];
    uint16_t ethertype;
};

#endif

