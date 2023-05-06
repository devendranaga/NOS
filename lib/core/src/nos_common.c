#include <stdio.h>
#include <stdint.h>
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
