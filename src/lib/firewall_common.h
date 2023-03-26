#ifndef __FIREWALL_COMMON_H__
#define __FIREWALL_COMMON_H__

#include <stdio.h>
#include <stdint.h>

#define INLINE inline
#define CONST const
#define STATIC static

void fw_hexdump(const char *msg, uint8_t *pkt, uint32_t pkt_len);

#endif
