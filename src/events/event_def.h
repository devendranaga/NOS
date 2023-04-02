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

    FW_EVENT_DESCR_ETH_SRC_DST_ARE_BROADCAST,
    FW_EVENT_DESCR_ETH_SRC_DST_ARE_ZERO,

    FW_EVENT_DESCR_ETH_UNSPPORTED_ETHERTYPE,

    FW_EVENT_DESCR_ARP_HWTYPE_INVAL,
    FW_EVENT_DESCR_ARP_HDR_LEN_TOO_SHORT,
    FW_EVENT_DESCR_ARP_INVAL_HWADDR_LEN,
    FW_EVENT_DESCR_ARP_INVAL_PROTO_ADDR_LEN,
    FW_EVENT_DESCR_ARP_OP_INVAL,
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

    struct fw_event         *next;
};

typedef struct fw_event fw_event_t;

#endif

