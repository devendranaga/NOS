#ifndef __FW_EVENT_DEF_H__
#define __FW_EVENT_DEF_H__

enum fw_event_type {
    FW_EVEN_DENY,
    FW_EVENT_ALLOW,
    FW_EVENT_SRC_DST_ARE_BROADCAST,
    FW_EVENT_SRC_DST_ARE_ZERO,
};

typedef enum fw_event_type fw_event_type_t;

#endif

