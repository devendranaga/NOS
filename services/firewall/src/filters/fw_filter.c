#include <fw_filter.h>

static fw_event_details_t fw_filter_icmp_run(
                        fw_rule_config_item_t *rule,
                        fw_packet_t *pkt)
{
    return FW_EVENT_DESCR_DENY;
}

static fw_event_details_t fw_filter_arp_run(
                        fw_rule_config_item_t *rule,
                        fw_packet_t *pkt)
{
    return FW_EVENT_DESCR_DENY;
}

static const struct fw_filter {
    rule_protocol_type_t protocol_type;
    fw_event_details_t (*filter_fn)(fw_rule_config_item_t *rule,
                                    fw_packet_t *pkt);
} fw_filter_set[] = {
    {RULE_PROTOCOL_TYPE_ICMP, fw_filter_icmp_run},
    {RULE_PROTOCOL_TYPE_ARP, fw_filter_arp_run},
};

static rule_protocol_type_t map_protocol_type(fw_packet_t *pkt)
{
    if (pkt->pkt_rank == FW_PROTO_ARP_H) {
        return RULE_PROTOCOL_TYPE_ARP;
    } else if (pkt->pkt_rank == FW_PROTO_ICMP_H) {
        return RULE_PROTOCOL_TYPE_ICMP;
    }

    return RULE_PROTOCOL_TYPE_INVAL;
}

fw_event_details_t fw_filter_run(fw_rule_config_data_t *rule_config,
                                 fw_packet_t *pkt)
{
    fw_event_details_t evt_descr = FW_EVENT_DESCR_DENY;
    rule_protocol_type_t rule_proto;
    fw_rule_config_item_t *rule;
    uint32_t i;

    rule_proto = map_protocol_type(pkt);
    for (rule = rule_config->head; rule; rule = rule->next) {
        for (i = 0; i < SIZEOF(fw_filter_set); i ++) {
            if (fw_filter_set[i].protocol_type == rule_proto) {
                evt_descr = fw_filter_set[i].filter_fn(rule, pkt);
                if (evt_descr != FW_EVENT_DESCR_ALLOW) {
                    break;
                }
            }
        }
    }

    return evt_descr;
}

