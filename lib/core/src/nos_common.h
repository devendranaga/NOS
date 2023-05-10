
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void nos_hexdump_crypto(const char *name, uint8_t *buf, uint32_t buf_len);
void nos_hexdump_network(const char *name, uint8_t *buf, uint32_t buf_len);
int nos_util_convert_u32(const char *str, uint32_t *val);
int nos_util_convert_i32(const char *str, int32_t *val);

#ifdef __cplusplus
}
#endif

