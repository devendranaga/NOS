/**
 * @brief - Implements Firewall Config.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <firewall_config.h>

/**
 * -i -> interface list separated by comma.
 * -e -> event transport type tcp,udp or mqtt.
 * -I -> ip and port of the event server.
 * -t -> mqtt topic
 */
#define CMD_ARGS_LIST "i:e:t:u:q"

STATIC void usage(const char *progname)
{
    fprintf(stderr, "<%s> -i <interface list separated by comma>\n"
                    "\t -e <event transport type : tcp, udp, mqtt>\n"
                    "\t -I <ip port of the event server in ip:port format>\n"
                    "\t -t <mqtt topic>\n",
                    progname);
}

/* Get all interfaces passed via command line. */
STATIC void fw_get_interface_list(const char *iflist,
                                  fw_command_args_t *cmd_args)
{
    uint32_t len = strlen(iflist);
    uint32_t count = 0;
    uint32_t i = 0;

    /* Read all interfaces. */
    while (i < len) {
        if (iflist[i] == ',') {
            cmd_args->if_list[cmd_args->n_iflist][count] = '\0';
            cmd_args->n_iflist ++;
            count = 0;
        } else {
            cmd_args->if_list[cmd_args->n_iflist][count] = iflist[i];
            count ++;
        }
        i ++;
    }
    /* Last one does not end with ',' and stops with \0. */
    cmd_args->if_list[cmd_args->n_iflist][count] = '\0';
    cmd_args->n_iflist ++;
}

/* Get the Event Transport Type. */
STATIC int fw_get_event_transport_type(const char *optarg,
                                       fw_command_args_t *cmd_args)
{
    if (!strcasecmp(optarg, "tcp")) {
        cmd_args->event_config.evt_transport_type = FW_EVENT_TRANSPORT_TCP;
    } else if (!strcasecmp(optarg, "udp")) {
        cmd_args->event_config.evt_transport_type = FW_EVENT_TRANSPORT_UDP;
    } else if (!strcasecmp(optarg, "mqtt")) {
        cmd_args->event_config.evt_transport_type = FW_EVENT_TRANSPORT_MQTT;
    } else {
        return -1;
    }

    return 0;
}

/* Get Event Transport IP and Port. */
STATIC int fw_get_event_transport(const char *optarg,
                                  fw_command_args_t *cmd_args)
{
    char *err_ptr = NULL;
    char tcp_port[20] = {0};
    int i = 0;
    int j = 0;

    while (optarg[i] != ':') {
        cmd_args->event_config.ip[i] = optarg[i];
        i ++;
    }
    cmd_args->event_config.ip[i] = '\0';

    while (optarg[i] != '\0') {
        tcp_port[j] = optarg[i];
        i ++;
    }
    cmd_args->event_config.port = strtoul(tcp_port, &err_ptr, 10);
    if (err_ptr && (*err_ptr != '\0')) {
        return -1;
    }

    return 0;
}

/* Get MQTT topic name. */
STATIC INLINE void fw_get_event_transport_mqtt_topic(const char *optarg,
                                                     fw_command_args_t *cmd_args)
{
    strcpy(cmd_args->event_config.mqtt_topic, optarg);
}

/* Parse command line arguments. */
int fw_parse_command_args(int argc, char **argv,
                          fw_command_args_t *fw_args)
{
    int ret;

    while ((ret = getopt(argc, argv, CMD_ARGS_LIST)) != -1) {
        switch (ret) {
            case 'i':
                fw_get_interface_list(optarg, fw_args);
            break;
            case 'e':
                ret = fw_get_event_transport_type(optarg, fw_args);
                if (ret < 0) {
                    usage(argv[0]);
                    return -1;
                }
            break;
            case 'I':
                ret = fw_get_event_transport(optarg, fw_args);
                if (ret < 0) {
                    usage(argv[0]);
                    return -1;
                }
            break;
            case 't':
                fw_get_event_transport_mqtt_topic(optarg, fw_args);
            break;
            default:
                usage(argv[0]);
            return -1;
        }
    }

    return 0;
}


