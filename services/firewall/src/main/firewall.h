/**
 * @brief - Defines Firewall context.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FIREWALL_H__
#define __FIREWALL_H__

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <firewall_config.h>
#include <driver_generic.h>
#include <firewall_common.h>
#include <os_thread.h>
#include <fw_pkt.h>
#include <protocol_generic.h>
#include <debug.h>
#include <os.h>
#include <os_signal.h>
#include <events.h>
#include <fw_config.h>
#include <nos_fw_stats.h>
#include <fw_rules.h>
#include <fw_filter.h>

/* Firewall interface context. */
struct firewall_interface_context {
    /* Underlying interface name. */
    char ifname[20];

    /* Underlying driver sock. */
    void *raw_ctx;

    /* Receive thread. */
    void *rx_thr;

    /* Processing thread. */
    void *process_thr;

    /* Packet Queue pointer. */
    void *pkt_q;

    /* Event Context. */
    void *evt_ctx;

    /* Driver callbacks. */
    struct nw_driver_callbacks *nw_drv;

    struct os_mutex pkt_rx_evt_lock;
    struct os_cond pkt_rx_evt_cond;

    fw_rule_config_data_t *rule_config;

    /* Firewall stats. */
    nos_fw_stats_intf_t stats;
};

typedef struct firewall_interface_context firewall_interface_context_t;

/* Firewall context. */
struct firewall_context {
    /* Command line arguments. */
    fw_command_args_t args;

    /* Callback pointer set. */
    struct nw_driver_callbacks nw_drv;

    int n_intf;
    firewall_interface_context_t if_list[MAX_IFS];

    /* Base configuration info. */
    fw_base_conf_t base_conf;

    /* Fw rules. */
    fw_rule_config_data_t *rule_config;
};

typedef struct firewall_context firewall_context_t;

#endif

