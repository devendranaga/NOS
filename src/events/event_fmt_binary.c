#include <stdint.h>
#include <event_def.h>
#include <event_fmt_binary.h>
#include <firewall_common.h>

uint32_t fw_event_fmt_binary_serialize(fw_event_t *event,
                                       fw_event_fmt_binary_t *binary)
{
    binary->evt_type = event->event;
    binary->evt_description = event->event_details;
    binary->rule_id = event->rule_id;

    return sizeof(*binary);
}
