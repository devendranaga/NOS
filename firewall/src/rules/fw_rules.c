#include <stdio.h>
#include <stdlib.h>
#include <fw_rules.h>
#include <firewall_common.h>

STATIC int fw_rule_read(const char *data, struct rule_config_data *rule_data)
{
    return 0;
}

void *fw_rule_init(const char *rule_file)
{
    struct rule_config_data *rule_data;
    char data[1024];
    FILE *fp;
    int ret;

    rule_data = calloc(1, sizeof(struct rule_config_data));
    if (!rule_data) {
        return NULL;
    }

    fp = fopen(rule_file, "r");
    if (!fp) {
        return NULL;
    }

    while (1) {
        fgets(data, sizeof(data), fp);
        ret = fw_rule_read(data, rule_data);
        if (ret < 0) {
            goto err;
        }
    }

    return rule_data;

err:
    if (rule_data) {
        free(rule_data);
    }

    return NULL;
}

