#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fw_rules.h>
#include <firewall_common.h>

static const struct rule_action_list {
    rule_action_t action;
    const char *action_str;
} rule_action_list[] = {
    {RULE_ACTION_LOG,       "log"},
    {RULE_ACTION_DROP,      "drop"},
    {RULE_ACTION_ALERT,     "alert"},
};

static const struct rule_protocol_list {
    rule_protocol_type_t protocol_type;
    const char *protocol_str;
} rule_protocol_list[] = {
    {RULE_PROTOCOL_TYPE_ICMP, "icmp"},
    {RULE_PROTOCOL_TYPE_ARP, "arp"},
};

static const struct rule_layer_list {
    rule_layer_t layer;
    const char *layer_str;
} rule_layer_list[] = {
    {RULE_LAYER_MAC,    "from_mac"},
    {RULE_LAYER_IPV4,   "from_ipv4"},
    {RULE_LAYER_MAC,    "to_mac"},
    {RULE_LAYER_IPV4,   "to_ipv4"},
};

STATIC rule_action_t fw_rule_get_rule_action(const char *data)
{
    for (uint32_t i = 0; i < sizeof(rule_action_list) /
                             sizeof(rule_action_list[0]); i ++) {
        if (!strcmp(rule_action_list[i].action_str, data)) {
            return rule_action_list[i].action;
        }
    }

    return RULE_ACTION_INVAL;
}

STATIC rule_protocol_type_t fw_rule_get_rule_protocol_type(const char *data)
{
    for (uint32_t i = 0; i < sizeof(rule_protocol_list) /
                             sizeof(rule_protocol_list[0]); i ++) {
        if (!strcmp(rule_protocol_list[i].protocol_str, data)) {
            return rule_protocol_list[i].protocol_type;
        }
    }

    return RULE_PROTOCOL_TYPE_INVAL;
}

STATIC rule_layer_t fw_rule_get_rule_layer(const char *data)
{
    for (uint32_t i = 0; i < sizeof(rule_layer_list) /
                             sizeof(rule_layer_list[0]); i ++) {
        if (!strcmp(rule_layer_list[i].layer_str, data)) {
            return rule_layer_list[i].layer;
        }
    }

    return RULE_LAYER_INVAL;
}

STATIC int fw_rule_get_macaddr(const char *macaddr_str,
                               uint8_t *macaddr)
{
    uint32_t mac[6];
    int ret;

    ret = sscanf(macaddr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                            &mac[0], &mac[1], &mac[2],
                            &mac[3], &mac[4], &mac[5]);
    if (ret != 6) {
        return -1;
    }

    macaddr[0] = mac[0];
    macaddr[1] = mac[1];
    macaddr[2] = mac[2];
    macaddr[3] = mac[3];
    macaddr[4] = mac[4];
    macaddr[5] = mac[5];

    return 0;
}

STATIC int fw_rule_parse_mac_pair(const char *data,
                                  uint8_t *any_from_mac,
                                  uint8_t *from_mac)
{
    int ret = -1;

    *any_from_mac = 0;

    if (!strcmp(data, "any")) {
        *any_from_mac = 1;
        ret = 0;
    } else {
        ret = fw_rule_get_macaddr(data, from_mac);
    }

    return ret;
}

STATIC int fw_rule_parse_uint32(const char *val, uint32_t *data)
{
    char *err = NULL;

    *data = strtoul(val, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }
    return 0;
}

STATIC int fw_rule_parse_ipv4_port(const char *data,
                                   uint8_t *any_from_ip,
                                   uint32_t *from_ipv4,
                                   uint32_t *from_port)
{
    int ret = -1;

    if (!strcmp(data, "any:any")) {
        *any_from_ip = 1;
        ret = 0;
    } else if (!strcmp(data, "$HOME:any")) {
        /* Skip this for now. */
        *any_from_ip = 1;
        ret = 0;
    } else {
        char t[64];
        int i = 0;
        int j =0;

        while (data[i] != ':') {
            t[i] = data[i];
            i ++;
        }
        i ++;
        t[i] = '\0';

        ret = fw_rule_parse_uint32(t, from_ipv4);
        if (ret != 0) {
            return -1;
        }

        while (data[i] != '\0') {
            t[j] = data[i];
            i ++;
            j ++;
        }
        t[j] = '\0';

        ret = fw_rule_parse_uint32(t, from_port);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static int fw_rule_parse_var_val(const char *data,
                                 char *var, char *val)
{
    int i = 0;
    int j = 0;

    i ++; /* Skip (. */

    while (data[i] != ':') {
        var[j] = data[i];
        j ++;
        i ++;
    }
    var[j] = '\0';
    j = 0;
    i ++;

    /* Skip spaces in between. */
    while (data[i] == ' ') { i ++; }

    if (data[i] == '"') {
        i ++;
    }

    while (data[i] != ';') {
        if ((data[i] == '"') || (data[i] == ')')) {
            i ++;
            break;
        }
        val[j] = data[i];
        j ++;
        i ++;
    }
    i ++;
    val[j] = '\0';

    return i;
}

STATIC int fw_rule_parse_msg_rule_id(const char *data,
                                     fw_rule_config_item_t *rule)
{
    char val[512] = {0};
    char var[10] = {0};
    int off = 0;
    int ret;

    off = fw_rule_parse_var_val(&data[off], var, val);
    if (off <= 0) {
        return -1;
    }

    rule->msg = strdup(val);
    rule->msg_len = strlen(val);

    off = fw_rule_parse_var_val(&data[off], var, val);
    if (off <= 0) {
        return -1;
    }

    ret = fw_rule_parse_uint32(val, &rule->rule_id);

    return ret;
}

STATIC int fw_rule_read(const char *data, int len,
                        fw_rule_config_item_t *rule)
{
    char tokens[10][512];
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t k = 0;
    int ret;

    while (data[i] != '\0') {
        if (data[i] == '(') {
            while (data[i] != ')') {
                tokens[j][k] = data[i];
                i ++;
                k ++;
            }
            i ++;
            tokens[j][k] = ')';
            tokens[j][k + 1] = '\0';
        } else {
            while (data[i] != ' ') {
                tokens[j][k] = data[i];
                i ++;
                k ++;
            }
            i ++; // skip ' '
            tokens[j][k] = '\0';
        }
        k = 0;
        j ++;
    }

    for (i = 0; i < j; i ++) {
        switch (i) {
            case 0:
                rule->rule_action = fw_rule_get_rule_action(tokens[i]);
            break;
            case 1:
                rule->proto_type = fw_rule_get_rule_protocol_type(tokens[i]);
            break;
            case 2:
                rule->from_rule = fw_rule_get_rule_layer(tokens[i]);
            break;
            case 3: {
                switch (rule->from_rule) {
                    case RULE_LAYER_MAC:
                        ret = fw_rule_parse_mac_pair(tokens[i],
                                                     &rule->any_from_mac,
                                                     rule->from_mac);
                        if (ret < 0) {
                            return -1;
                        }
                    break;
                    case RULE_LAYER_IPV4:
                        ret = fw_rule_parse_ipv4_port(tokens[i],
                                                      &rule->any_from_ip,
                                                      &rule->from_ipv4,
                                                      &rule->from_port);
                        if (ret < 0) {
                            return -1;
                        }
                    break;
                    default:
                        return -1;
                }
            } break;
            case 4:
                rule->to_rule = fw_rule_get_rule_layer(tokens[i]);
            break;
            case 5: {
                switch (rule->to_rule) {
                    case RULE_LAYER_MAC:
                        ret = fw_rule_parse_mac_pair(tokens[i],
                                                     &rule->any_to_mac,
                                                     rule->to_mac);
                        if (ret < 0) {
                            return -1;
                        }
                    break;
                    case RULE_LAYER_IPV4:
                        ret = fw_rule_parse_ipv4_port(tokens[i],
                                                      &rule->any_to_ipv4,
                                                      &rule->to_ipv4,
                                                      &rule->to_port);
                        if (ret < 0) {
                            return -1;
                        }
                    break;
                    default:
                        return -1;
                }
            } break;
            case 6: {
                ret = fw_rule_parse_msg_rule_id(tokens[i], rule);
            } break;
        }
    }

    return 0;
}

void *fw_rule_init(const char *rule_file)
{
    fw_rule_config_data_t *rule_data;
    char data[1024];
    FILE *fp;
    int ret;

    rule_data = calloc(1, sizeof(fw_rule_config_data_t));
    if (!rule_data) {
        return NULL;
    }

    fp = fopen(rule_file, "r");
    if (!fp) {
        return NULL;
    }

    while (fgets(data, sizeof(data), fp) != NULL) {
        fw_rule_config_item_t *item;

        int len = strlen(data) - 1;

        item = calloc(1, sizeof(fw_rule_config_item_t));
        if (!item) {
            return NULL;
        }

        data[len] = '\0';
        ret = fw_rule_read(data, len, item);
        if (ret < 0) {
            goto err;
        }

        if (!rule_data->head) {
            rule_data->head = item;
            rule_data->tail = item;
        } else {
            rule_data->tail->next = item;
            rule_data->tail = item;
        }
    }

    fclose(fp);

    return rule_data;

err:
    if (rule_data) {
        free(rule_data);
    }

    return NULL;
}

void fw_rule_deinit(void *ptr)
{
    fw_rule_config_data_t *rules = ptr;
    fw_rule_config_item_t *rule = rules->head;
    fw_rule_config_item_t *tmp = rule;

    while (rule) {
        tmp = rule;
        rule = rule->next;
        free(tmp);
    }
}

