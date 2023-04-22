#ifndef __FW_RULES_H__
#define __FW_RULES_H__

#include <stdint.h>

enum rule_action {
    RULE_ACTION_LOG,
    RULE_ACTION_DROP,
    RULE_ACTION_ALERT,
};

typedef enum rule_action rule_action_t;

enum rule_protocol_type {
    RULE_PROTOCOL_TYPE_ICMP,
    RULE_PROTOCOL_TYPE_ARP,
};

typedef enum rule_protocol_type rule_protocol_type_t;

struct fw_rule_config_item {
    rule_action_t rule_action;
    rule_protocol_type_t proto_type;
    uint32_t from_ipv4;
    uint32_t from_port;
    uint32_t to_ipv4;
    uint32_t to_port;
    char *msg;
    uint32_t msg_len;
    uint32_t rule_id;

    struct fw_rule_config_item *next;
};

typedef struct fw_rule_config_item fw_rule_config_item_t;

struct rule_config_data {
    fw_rule_config_item_t *head;
    fw_rule_config_item_t *tail;
};

#endif

