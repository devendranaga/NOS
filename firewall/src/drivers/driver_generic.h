#ifndef __FIRWEALL_DRIVER_GENERIC_H__
#define __FIRWEALL_DRIVER_GENERIC_H__

#include <stdint.h>

struct nw_driver_callbacks {
    /* Initialize network device. */
    void * (*init)(const char *);
    void (*deinit)(void *);
    int (*read)(void *, uint8_t *msg, uint32_t len);
    int (*write)(void *, uint8_t *msg, uint32_t len);
};

void nw_driver_register(struct nw_driver_callbacks *nw_drv);

#endif

