#ifndef __FW_RULES_H__
#define __FW_RULES_H__

#include <stdint.h>

typedef enum rule_action {
    RULE_ACTION_LOG,
    RULE_ACTION_DROP,
    RULE_ACTION_ALERT,
    RULE_ACTION_INVAL,
} rule_action_t;

typedef enum rule_protocol_type {
    RULE_PROTOCOL_TYPE_ICMP,
    RULE_PROTOCOL_TYPE_ARP,
    RULE_PROTOCOL_TYPE_INVAL,
} rule_protocol_type_t;

typedef enum rule_layer {
    RULE_LAYER_MAC,
    RULE_LAYER_IPV4,
    RULE_LAYER_INVAL,
} rule_layer_t;

typedef struct fw_rule_config_item {
    rule_action_t           rule_action;
    rule_protocol_type_t    proto_type;
    rule_layer_t            from_rule;
    rule_layer_t            to_rule;
    uint8_t                 any_from_mac;
    uint8_t                 from_mac[6];
    uint8_t                 any_to_mac;
    uint8_t                 to_mac[6];
    uint8_t                 any_from_ip;
    uint32_t                from_ipv4;
    uint32_t                from_port;
    uint8_t                 any_to_ipv4;
    uint32_t                to_ipv4;
    uint32_t                to_port;
    char                    *msg;
    uint32_t                msg_len;
    uint32_t                rule_id;

    struct fw_rule_config_item *next;
} fw_rule_config_item_t;

typedef struct fw_rule_config_data {
    fw_rule_config_item_t *head;
    fw_rule_config_item_t *tail;
} fw_rule_config_data_t;

void *fw_rule_init(const char *rule_file);
void fw_rule_deinit(void *ptr);

#endif

