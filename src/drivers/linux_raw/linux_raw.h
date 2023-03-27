/**
 * @brief - Implements Raw socket interface.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __FIREWALL_LINUX_RAW_H__
#define __FIREWALL_LINUX_RAW_H__

#include <driver_generic.h>

void *linux_raw_init(const char *device_name);
void linux_raw_deinit(void *ctx);
int linux_raw_read(void *ctx, uint8_t *msg, uint32_t len);
int linux_raw_write(void *ctx, uint8_t *msg, uint32_t len);

#endif
