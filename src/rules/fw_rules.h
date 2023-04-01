#ifndef __FW_RULES_H__
#define __FW_RULES_H__

enum rule_action {
    RULE_ACTION_LOG,
    RULE_ACTION_DROP,
    RULE_ACTION_ALERT,
};

typedef enum rule_action rule_action_t;

#endif

