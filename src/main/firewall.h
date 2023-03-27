#ifndef __FIREWALL_H__
#define __FIREWALL_H__

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
#include <protocol_generic.h>
#include <debug.h>
#include <os.h>

#define MAX_IFS 10
#define MAX_IFNAME_SIZE 15

/* Type of the event transport. */
enum fw_event_transport_type {
    FW_EVENT_TRANSPORT_TCP,
    FW_EVENT_TRANSPORT_UDP,
    FW_EVENT_TRANSPORT_MQTT,
    FW_EVENT_TRANSPORT_INVAL,
};

typedef enum fw_event_transport_type fw_event_transport_type_t;

struct fw_event_config {
    fw_event_transport_type_t evt_transport_type;
    char tcp_ip[20];
    int tcp_port;
};

typedef struct fw_event_config fw_event_config_t;

struct fw_command_args {
    char if_list[MAX_IFS][MAX_IFNAME_SIZE];
    uint32_t n_iflist;
    fw_event_config_t event_config;
};

typedef struct fw_command_args fw_command_args_t;

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

/* Firewall context. */
struct firewall_context {
    /* Command line arguments. */
    fw_command_args_t args;
    struct nw_driver_callbacks nw_drv;
    int n_intf;
    struct firewall_interface_context if_list[MAX_IFS];
};

#endif

