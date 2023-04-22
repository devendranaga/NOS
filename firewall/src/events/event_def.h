/**
 * @brief - Definition of events with event type.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FW_EVENT_DEF_H__
#define __FW_EVENT_DEF_H__

#include <stdint.h>

/* Details of the Firewall Events. */
enum fw_event_details {
    FW_EVENT_DESCR_DENY,
    FW_EVENT_DESCR_ALLOW,

    FW_EVENT_DESCR_ETH_SRC_DST_ARE_BROADCAST, /* Both are broadcast. */
    FW_EVENT_DESCR_ETH_SRC_DST_ARE_ZERO, /* Both are zeros. */

    FW_EVENT_DESCR_ETH_UNSPPORTED_ETHERTYPE, /* Unsupported ethertype for this firewall. */

    FW_EVENT_DESCR_ARP_HWTYPE_INVAL, /* ARP hardware type is invalid. */
    FW_EVENT_DESCR_ARP_HDR_LEN_TOO_SHORT, /* ARP Header length is too short. */
    FW_EVENT_DESCR_ARP_INVAL_HWADDR_LEN, /* ARP invalid Hardware address length. */
    FW_EVENT_DESCR_ARP_INVAL_PROTO_ADDR_LEN, /* ARP Invalid Protocol Address Length. */
    FW_EVENT_DESCR_ARP_OP_INVAL, /* ARP op field is invalid. */

    FW_EVENT_DESCR_IEEE8021AE_HDRLEN_TOO_SMALL, /* IEEE 802.1AE length too short. */

    FW_EVENT_DESCR_IPV4_INVAL_VERSION, /* IPv4 invalid version. */
    FW_EVENT_DESCR_IPV4_HDR_LEN_TOO_SMALL, /* IPv4 header length is too small. */
    FW_EVENT_DESCR_IPV4_FLAGS_RESERVED_SET, /* IPv4 reserved bits are set. */
    FW_EVENT_DESCR_IPV4_FLAGS_BOTH_MF_DF_SET, /* IPv4 both MF and DF bits are set. */
    FW_EVENT_DESCR_IPV4_TTL_ZERO, /* IPv4 TTL is zero. */
    FW_EVENT_DESCR_IPV4_UNSUPPORTED_PROTOCOL,

    FW_EVENT_DESCR_ICMP_INVAL,
    FW_EVENT_DESCR_ICMP_UNSUPPORTED_TYPE, /* Unsupported ICMP Type. */
    FW_EVENT_DESCR_ICMP_HDR_TOO_SMALL, /* Too small ICMP Header Length. */

    FW_EVENT_DESCR_TCP_HDR_FLAGS_NULL, /* TCP Flags are 0. */
    FW_EVENT_DESCR_TCP_RESERVED_FLAGS_SET, /* TCP Reserved flags are set. */
    FW_EVENT_DESCR_TCP_SRC_PORT_ZERO, /* TCP Source Port is 0. */
    FW_EVENT_DESCR_TCP_DST_PORT_ZERO, /* TCP Destination Port is 0. */
    FW_EVENT_DESCR_TCP_SYN_FIN_BOTH_SET, /* TCP SYN + FIN both are set. */
    FW_EVENT_DESCR_TCP_ALL_FLAGS_SET, /* TCP All flags are set. */

    FW_EVENT_DESCR_UDP_SRC_PORT_ZERO, /* UDP Source Port is 0. */
    FW_EVENT_DESCR_UDP_DST_PORT_ZERO, /* UDP Destination Port is 0. */
    FW_EVENT_DESCR_UDP_PAYLOAD_LEN_ZERO, /* UDP Payload length is 0. */

    FW_EVENT_DESCR_IPV6_HDRLEN_TOO_SMALL, /* IPv6 Header length too small. */

    FW_EVENT_DESCR_ICMP6_HDRLEN_TOO_SMALL, /* ICMP6 Header length too small. */
    FW_EVENT_DESCR_ICMP6_UNSUPPORTED_TYPE, /* ICMP6 Unsupported type. */

    FW_EVENT_DESCR_8021X_MKA_CKN_TOO_LARGE, /* 802.1x MKA CKN length too large. */
    FW_EVENT_DESCR_8021X_MKA_ALG_AGILITY_INVALID, /* 802.1x MKA Algorithm Agility unknown. */
    FW_EVENT_DESCR_8021X_MKA_VERSION_OUT_OF_RANGE, /* 802.1x MKA Version out of range. */
    FW_EVENT_DESCR_8021X_MKA_INVAL_PARAMSET_TYPE, /* 802.1x MKA Invalid parameter set length. */

    FW_EVENT_DESCR_DHCP_PARAMSET_UNKNOWN, /* DHCP Parameter set unknown. */
    FW_EVENT_DESCR_DHCP_MAGIC_COOKIE_INVALID, /* DHCP Magic cookie is invalid. */
};

typedef enum fw_event_details fw_event_details_t;

/* Type of the Event. */
enum fw_event_type {
    FW_EVENT_ALLOW,
    FW_EVENT_DENY,
    FW_EVENT_NOTIFY,
};

/* Get Type based on Details. */
#define FW_EVENT_GET_TYPE(__type, __details) {\
    if (__details != FW_EVENT_DESCR_ALLOW) {\
        __type = FW_EVENT_DENY;\
    }\
    if (__details == FW_EVENT_DESCR_ALLOW) {\
        __type = FW_EVENT_ALLOW;\
    }\
}

typedef enum fw_event_type fw_event_type_t;

#define FW_EVENT_MAX_IFNAME_SIZE    16
#define FW_EVENT_IPV6_ADDR_LEN      16

enum fw_event_protocol {
    FW_EVENT_PROTOCOL_NONE,
    FW_EVENT_PROTOCOL_TCP,
    FW_EVENT_PROTOCOL_UDP,
    FW_EVENT_PROTOCOL_ICMP,
    FW_EVENT_PROTOCOL_PTP,
};

typedef enum fw_event_protocol fw_event_protocol_t;

/* Event definition per protocol description. */
struct fw_protocol_event {
    uint16_t                ethertype;
    uint16_t                vid;
    uint32_t                src_ipv4;
    uint32_t                dst_ipv4;
    uint8_t                 src_ipv6[FW_EVENT_IPV6_ADDR_LEN];
    uint8_t                 dst_ipv6[FW_EVENT_IPV6_ADDR_LEN];
    fw_event_protocol_t     protocol;
    uint16_t                src_port;
    uint16_t                dst_port;
};

typedef struct fw_protocol_event fw_protocol_event_t;

struct fw_event {
    /* Base level of the event. */
    fw_event_type_t         event;

    /* Details of what has happened. */
    fw_event_details_t      event_details;
    char                    ifname[FW_EVENT_MAX_IFNAME_SIZE];

    /* 0 for auto detected events. Otherwise a valid value from the rules. */
    uint32_t                rule_id;

    /* If its a protocol, then describe what it is. */
    fw_protocol_event_t     protocol_event;

    /* Message length in bytes. */
    uint16_t                msg_len;

    /* Optional message given by the rule file. */
    char                    *msg;

    /* Sample packet bytes if more description needed in the event. */
    uint8_t                 *pkt;

    /* Packet length. */
    uint16_t                pkt_len;

    struct fw_event         *next;
};

typedef struct fw_event fw_event_t;

#endif

