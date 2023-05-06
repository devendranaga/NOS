/**
 * @brief - Implements configuration parser.
 *
 * @copyright - 2023-present All rights reserved. Ask for License.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <nos_config_parser.h>

static inline void nos_config_parser_skip_space(const char *data, int *i)
{
    while (data[*i] == ' ') {
        (*i) ++;
    }
}

static int nos_config_parser_get_var_val(const char *data,
                                         int len, char *var, char *val)
{
    int i = 0;
    int j = 0;

    /* Skip the comments. */
    if (data[0] == '#') {
        return 0;
    }

    /* Skip the spaces.. */
    nos_config_parser_skip_space(data, &i);

    /* Get var . */
    while ((data[i] != '=') && (data[i] != '\0')) {
        if (data[i] == ' ') {
            i ++;
            break;
        }
        var[i] = data[i];
        i ++;
    }
    var[i] = '\0';
    i ++;

    /* Skip the spaces.. */
    nos_config_parser_skip_space(data, &i);

    /* Get val. */
    j = 0;
    while ((data[i] != '\0') && (data[i] != '#')) {
        if (data[i] != '"') {
            val[j] = data[i];
            j ++;
        }
        i ++;
    }
    val[j] = '\0';

    return 0;
}

/* Get integer from the string. */
static int nos_config_parser_get_int(const char *str, int *data)
{
    char *err = NULL;

    *data = strtol(str, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

/* Get long long integer from the string. */
static int nos_config_parser_get_int64(const char *str, int64_t *data)
{
    char *err = NULL;

    *data = strtoll(str, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

/* Get unsigned integer from the string. */
static int nos_config_parser_get_uint(const char *str, uint32_t *data)
{
    char *err = NULL;

    *data = strtoul(str, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

/* Get long long unsigned integer from the string. */
static int nos_config_parser_get_uint64(const char *str, uint64_t *data)
{
    char *err = NULL;

    *data = strtoull(str, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

/* Get hex from the string. */
static int nos_config_parser_get_hex(const char *str, uint32_t *data)
{
    char *err = NULL;

    *data = strtoul(str, &err, 16);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

static int parse_config_data(const char *buf,
                             int len,
                             nos_config_parser_config_data_t *config_data,
                             int config_data_len)
{
    char var[1024] = {0};
    char val[1024] = {0};
    int i = 0;

    nos_config_parser_get_var_val(buf, len, var, val);

    for (i = 0; i < config_data_len; i ++) {
        /* Copy the data back. */
        if (!strcmp(config_data[i].variable_name, var)) {
            switch (config_data[i].value_type) {
                case NOS_CONFIG_PARSER_VALUE_TYPE_INT: {
                    int *int_data = config_data[i].value_addr;

                    nos_config_parser_get_int(val, int_data);
                } break;
                case NOS_CONFIG_PARSER_VALUE_TYPE_UINT: {
                    uint32_t *uint_data = config_data[i].value_addr;

                    nos_config_parser_get_uint(val, uint_data);
                } break;
                case NOS_CONFIG_PARSER_VALUE_TYPE_INT64: {
                    int64_t *int64_data = config_data[i].value_addr;

                    nos_config_parser_get_int64(val, int64_data);
                } break;
                case NOS_CONFIG_PARSER_VALUE_TYPE_UINT64: {
                    uint64_t *uint64_data = config_data[i].value_addr;

                    nos_config_parser_get_uint64(val, uint64_data);
                } break;
                case NOS_CONFIG_PARSER_VALUE_TYPE_STRING: {
                    char *str_data = config_data[i].value_addr;

                    strcpy(str_data, val);
                } break;
                case NOS_CONFIG_PARSER_VALUE_TYPE_HEX: {
                    uint32_t *hex_data = config_data[i].value_addr;

                    nos_config_parser_get_hex(val, hex_data);
                } break;
                default: {
                    return -1;
                }
            }
            break;
        }
    }

    return 0;
}

int parse_configuration(const char *config,
                        nos_config_parser_config_data_t *config_data,
                        int config_data_len)
{
    char data[1024] = {0};
    void *ptr = NULL;
    FILE *fp;
    int len;
    int ret;

    fp = fopen(config, "r");
    if (!fp) {
        return -1;
    }

    while ((ptr = fgets(data, sizeof(data), fp)) != NULL) {
        len = strlen(data) - 1;
        data[len] = '\0';

        ret = parse_config_data(data, len, config_data, config_data_len);
        if (ret < 0) {
            break;
        }
    }

    fclose(fp);

    return ret;
}

