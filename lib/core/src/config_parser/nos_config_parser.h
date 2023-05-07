/**
 * @brief - Implements configuration parser header.
 *
 * @copyright - All rights reserved. 2023-present. Ask for License.
 */
#ifndef __NOS_CONFIG_PARSER_H__
#define __NOS_CONFIG_PARSER_H__

/* Type of Configuration value in the value_addr. */
typedef enum {
    NOS_CONFIG_PARSER_VALUE_TYPE_INT,
    NOS_CONFIG_PARSER_VALUE_TYPE_UINT,
    NOS_CONFIG_PARSER_VALUE_TYPE_INT64,
    NOS_CONFIG_PARSER_VALUE_TYPE_UINT64,
    NOS_CONFIG_PARSER_VALUE_TYPE_STRING,
    NOS_CONFIG_PARSER_VALUE_TYPE_HEX,
} nos_val_type_t;

/* Configuration parser meta data information. */
typedef struct nos_config_parser_config_data {
    char            *variable_name;
    nos_val_type_t  value_type;
    void            *value_addr;
} nos_config_parser_config_data_t;

/**
 * @brief - Parse configuration file.
 *
 * @param[in] config_file - input configuration file
 * @param[in] config_data - configuration metadata pointer
 * @param[in] config_data_len - length of configuration metadata.
 *
 * @return 0 on success -1 on failure.
 */
int parse_configuration(const char *config_file,
                        nos_config_parser_config_data_t *config_data,
                        int config_data_len);

#endif

