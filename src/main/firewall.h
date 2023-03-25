#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <driver_generic.h>
#include <firewall_common.h>
#include <os_thread.h>
#include <fw_pkt.h>

#define MAX_IFS 10
#define MAX_IFNAME_SIZE 15

struct firewall_command_args {
    char if_list[MAX_IFS][MAX_IFNAME_SIZE];
    uint32_t n_iflist;
};

/* Firewall interface context. */
struct firewall_interface_context {
    /* Underlying driver sock. */
    void *raw_ctx;

    /* Receive thread. */
    void *rx_thr;

    /* Processing thread. */
    void *process_thr;

    /* Packet Queue pointer. */
    void *pkt_q;

    /* Driver callbacks. */
    struct nw_driver_callbacks *nw_drv;

    struct os_mutex pkt_rx_evt_lock;
    struct os_cond pkt_rx_evt_cond;
};

struct firewall_context {
    struct firewall_command_args args;
    struct nw_driver_callbacks nw_drv;
    int n_intf;
    struct firewall_interface_context if_list[MAX_IFS];
};
