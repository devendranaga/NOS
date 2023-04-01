#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <fw_config.h>
#include <firewall_common.h>

STATIC int fw_base_get_var_val(FILE *fp, char *var, char *val)
{
    char buf[1024];
    char *line;
    int len = 0;
    int i = 0;
    int j = 0;

    line = fgets(buf, sizeof(buf), fp);
    if (!line) {
        return 1;
    }

    len = strlen(buf) - 1;
    buf[len] = '\0';

    while (i < len) {
        if (buf[i] == '=') {
            break;
        }

        var[i] = buf[i];
        i ++;
    }
    var[i] = '\0';
    i ++;

    while (i < len) {
        if (buf[i] != '"') {
            val[j] = buf[i];
            j ++;
        }
        i ++;
    }

    return 0;
}

#if 0
STATIC int fw_get_uint32(const char *var, uint32_t *var_u32)
{
    char *err = NULL;

    printf("val : '%s'\n", var);
    *var_u32 = strtoul(var, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}
#endif

STATIC uint32_t fw_get_ipv4(const char *ipaddr)
{
    return inet_addr(ipaddr);
}

STATIC int fw_get_home(const char *var, const char *val,
                       fw_base_conf_t *conf)
{
    conf->home = fw_get_ipv4(var);
    return 0;
}

STATIC int fw_get_rule_file(const char *var, const char *val,
                            fw_base_conf_t *conf)
{
    conf->rule_file = strdup(val);
    printf("rule file %s\n", conf->rule_file);
    return 0;
}

/* configuration callbacks. */
struct fw_config_params {
    const char *var;
    int (*callback)(const char *var,
                    const char *val,
                    fw_base_conf_t *conf);
} config_params[] = {
    {"HOME",        fw_get_home},
    {"rule_file",   fw_get_rule_file},
};

int fw_base_config_parse(const char *filename, fw_base_conf_t *conf)
{
    char var[1024] = {0};
    char val[1024] = {0};
    uint32_t i;
    FILE *fp;
    int ret;

    fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }

    while (1) {
        ret = fw_base_get_var_val(fp, var, val);
        if (ret != 0) {
            break;
        }

        for (i = 0; i < SIZEOF(config_params); i ++) {
            if (strcmp(var, config_params[i].var) == 0) {
                ret = config_params[i].callback(var, val, conf);
                if (ret < 0) {
                    break;
                }
            }
        }
    }

    return ret >= 0 ? 0 : -1;
}

