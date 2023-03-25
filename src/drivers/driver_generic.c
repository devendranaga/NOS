#include <stdint.h>
#include <driver_generic.h>
#include <linux_raw.h>

void nw_driver_register(struct nw_driver_callbacks *nw_drv)
{
#ifdef CONFIG_DRIVER_RAW_SOCKET
    nw_drv->init = linux_raw_init;
    nw_drv>deinit = linux_raw_deinit;
    nw_drv->read = linux_raw_read;
    nw_drv->write =  linux_raw_write;
#endif
}

