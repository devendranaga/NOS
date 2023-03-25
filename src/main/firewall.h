#include <stdint.h>
#include <pthread.h>
#include <driver_generic.h>

struct firewall_context {
    struct nw_driver_callbacks *nw_drv;
};
