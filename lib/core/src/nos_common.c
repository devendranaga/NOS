#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <nos_common.h>

void nos_hexdump_crypto(const char *name, uint8_t *buf, uint32_t buf_len)
{
    uint32_t i;

    fprintf(stderr, "[%s] : ", name);
    for (i = 0; i < buf_len; i ++) {
        fprintf(stderr, "%02x", buf[i]);
    }
    fprintf(stderr, "\n");
}

void nos_hexdump_network(const char *name, uint8_t *buf, uint32_t buf_len)
{
    uint32_t i;

    fprintf(stderr, "[%s] : ", name);
    for (i = 0; i < buf_len; i ++) {        
        if ((i != 0) && ((i % 8) == 0)) {
            fprintf(stderr, "  ");
        }
        if ((i % 16 == 0)) {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "%02x ", buf[i]);
    }
    fprintf(stderr, "\n");
}

int nos_util_convert_u32(const char *str, uint32_t *val)
{
    char *err = NULL;

    *val = strtoul(str, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

int nos_util_convert_i32(const char *str, int32_t *val)
{
    char *err = NULL;

    *val = strtol(str, &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}
