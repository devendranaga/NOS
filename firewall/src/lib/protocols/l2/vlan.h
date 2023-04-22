/**
 * @brief - Implements VLAN header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_VLAN_H__
#define __LIB_PROTOCOLS_VLAN_H__

#include <stdbool.h>

struct vlan_header {
    uint8_t pcp; /* 3 bits. Priority Code Point. */
    bool dei; /* 1 bit. */
    uint16_t vid; /* 12 bits. */
    uint16_t ethertype; /* 16 bits. */
};

typedef struct vlan_header vlan_header_t;

#endif

