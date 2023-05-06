typedef enum {
    NOS_CONFIG_PARSER_VALUE_TYPE_INT,
    NOS_CONFIG_PARSER_VALUE_TYPE_UINT,
    NOS_CONFIG_PARSER_VALUE_TYPE_INT64,
    NOS_CONFIG_PARSER_VALUE_TYPE_UINT64,
    NOS_CONFIG_PARSER_VALUE_TYPE_STRING,
    NOS_CONFIG_PARSER_VALUE_TYPE_HEX,
} value_type_t;

typedef struct nos_config_parser_config_data {
    char *variable_name;
    value_type_t value_type;
    void *value_addr;
} nos_config_parser_config_data_t;

int parse_configuration(const char *config,
                        nos_config_parser_config_data_t *config_data,
                        int config_data_len);
