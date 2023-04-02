/**
 * @brief - Defines Firewall configuration.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FIREWALL_CONFIG_H__
#define __FIREWALL_CONFIG_H__

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <debug.h>
#include <firewall_common.h>

#define MAX_IFS             10
#define MAX_IFNAME_SIZE     15

/* Type of the event transport. */
enum fw_event_transport_type {
    FW_EVENT_TRANSPORT_UDP,
    FW_EVENT_TRANSPORT_TCP,
    FW_EVENT_TRANSPORT_MQTT,
    FW_EVENT_TRANSPORT_INVAL,
};

typedef enum fw_event_transport_type fw_event_transport_type_t;

enum fw_event_format_type {
    FW_EVENT_FORMAT_BINARY,
    FW_EVENT_FORMAT_CSV,
};

typedef enum fw_event_format_type fw_event_format_type_t;

/* Firewall event configuration. */
struct fw_event_config {
    fw_event_transport_type_t evt_transport_type;
    fw_event_format_type_t evt_format_type;
    char ip[20];
    int port;
    char mqtt_topic[128];
    bool log_to_file;
    char event_log_file[128];
};

typedef struct fw_event_config fw_event_config_t;

/* command line arguments. */
struct fw_command_args {
    char if_list[MAX_IFS][MAX_IFNAME_SIZE];
    uint32_t n_iflist;

    /* Event configuration. */
    fw_event_config_t event_config;

    /* Firewall configuration. */
    char config_file[128];
};

typedef struct fw_command_args fw_command_args_t;

/**
 * @brief - Parse command line arguments and place them into fw_args.
 *
 * @param [in] argc - input argc.
 * @param [in] argv - input argv.
 * @param [inout] fw_args - firewall argument pointer.
 *
 * @return 0 on succeess -1 on failure.
 */
int fw_parse_command_args(int argc, char **argv,
                          fw_command_args_t *fw_args);

#endif

