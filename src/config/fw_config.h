#ifndef __FW_CONFIG_H__
#define __FW_CONFIG_H__

#include <stdint.h>

struct fw_base_conf {
    uint32_t home;
    char *rule_file;
};

typedef struct fw_base_conf fw_base_conf_t;

int fw_base_config_parse(const char *filename, fw_base_conf_t *conf);

#endif

