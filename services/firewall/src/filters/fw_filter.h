#ifndef __FW_FILTER_H__
#define __FW_FILTER_H__

#include <protocol_generic.h>
#include <fw_rules.h>

fw_event_details_t fw_filter_run(fw_rule_config_data_t *rule_config,
                                 fw_packet_t *pkt);

#endif
