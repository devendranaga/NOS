#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <driver_generic.h>
#include <firewall_common.h>

#define MAX_IFS 10
#define MAX_IFNAME_SIZE 15

struct firewall_command_args {
    char if_list[MAX_IFS][MAX_IFNAME_SIZE];
    uint32_t n_iflist;
};

struct firewall_interface_context {
    void *raw_ctx;
};

struct firewall_context {
    struct firewall_command_args args;
    struct nw_driver_callbacks nw_drv;
    struct firewall_interface_context if_list[MAX_IFS];
};
