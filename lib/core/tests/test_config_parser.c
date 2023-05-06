/**
 * @brief Implement test code for configuration parser.
 * 
 * @copyright - 2023-present All rights reserved. Ask for License.
*/
#include <stdio.h>
#include <nos_core.h>

struct test_config {
    int int_data;
    char str_data[200];
    uint32_t hex_data;
};

int main(int argc, char **argv)
{
    struct test_config test_conf;

    nos_config_parser_config_data_t cfg_meta[] = {
        {
            .variable_name = "config_int",
            .value_type = NOS_CONFIG_PARSER_VALUE_TYPE_INT,
            .value_addr = &test_conf.int_data,
        },
        {
            .variable_name = "config_string",
            .value_type = NOS_CONFIG_PARSER_VALUE_TYPE_STRING,
            .value_addr = &test_conf.str_data[0],
        },
        {
            .variable_name = "config_hex",
            .value_type = NOS_CONFIG_PARSER_VALUE_TYPE_HEX,
            .value_addr = &test_conf.hex_data,
        }
    };
    int ret;

    ret = parse_configuration(argv[1], cfg_meta,
                              sizeof(cfg_meta) / sizeof(cfg_meta[0]));
    if (ret < 0) {
        return -1;
    }

    fprintf(stderr, "config_data: {\n");
    fprintf(stderr, "\t int_data: %d\n", test_conf.int_data);
    fprintf(stderr, "\t str_data: %s\n", test_conf.str_data);
    fprintf(stderr, "\t hex_data: 0x%x\n", test_conf.hex_data);
    fprintf(stderr, "}\n");

    return 0;
}
