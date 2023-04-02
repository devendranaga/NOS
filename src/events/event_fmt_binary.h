#ifndef __FW_EVENT_FMT_BINARY_H__
#define __FW_EVENT_FMT_BINARY_H__

#include <event_def.h>

struct fw_event_fmt_binary_protocol {
    uint16_t ethertype;
    uint16_t vid;
} __attribute__ ((__packed__));

typedef struct fw_event_fmt_binary_protocol fw_event_fmt_binary_protocol_t;

struct fw_event_fmt_binary {
    fw_event_type_t evt_type;
    fw_event_details_t evt_description;
    uint32_t rule_id;
    fw_event_fmt_binary_protocol_t protocol;
} __attribute__ ((__packed__));

typedef struct fw_event_fmt_binary fw_event_fmt_binary_t;

uint32_t fw_event_fmt_binary_serialize(fw_event_t *event,
                                       fw_event_fmt_binary_t *binary);

#endif
