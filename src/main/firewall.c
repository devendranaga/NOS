#include <firewall.h>

#define CMD_ARGS_LIST "i:"

#define MAX_THR_PRIO 1

STATIC void usage(const char *progname)
{
    fprintf(stderr, "<%s> -i <interface list separated by comma>",
                    progname);
}

/* Get all interfaces passed via command line. */
STATIC void get_interface_list(const char *iflist,
                               struct firewall_command_args *cmd_args)
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

/* Parse command line arguments. */
STATIC int parse_command_args(int argc, char **argv,
                              struct firewall_context *fw_ctx)
{
    int ret;

    while ((ret = getopt(argc, argv, CMD_ARGS_LIST)) != -1) {
        switch (ret) {
            case 'i':
                get_interface_list(optarg, &fw_ctx->args);
            break;
            default:
                usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

/* Process received packet. */
STATIC void * fw_process_packet(void *usr_ptr)
{
    struct firewall_interface_context *fw_if_ptr = usr_ptr;
    struct fw_packet *pkt;

    while (1) {
        os_mutex_lock(&fw_if_ptr->pkt_rx_evt_lock);
        os_cond_wait(&fw_if_ptr->pkt_rx_evt_cond, &fw_if_ptr->pkt_rx_evt_lock);
        while (1) {
            pkt = fw_packet_queue_first(fw_if_ptr->pkt_q);
            if (pkt == NULL) {
                break;
            }

            fw_debug(FW_DEBUG_LEVEL_VERBOSE, "parse rx msg of len [%d]\n",
                                                    pkt->total_len);
            fw_event_type_t type;
            type = parse_protocol(pkt);
            (void)type;

            free(pkt);
        }
        os_mutex_unlock(&fw_if_ptr->pkt_rx_evt_lock);
    }

    return NULL;
}

STATIC void * fw_recv_packet(void *usr_ptr)
{
    struct firewall_interface_context *fw_if_ptr = usr_ptr;
    int ret;

    while (1) {
        struct fw_packet *pkt;

        pkt = calloc(1, sizeof(struct fw_packet));
        if (!pkt) {
            break;
        }

        ret = fw_if_ptr->nw_drv->read(fw_if_ptr->raw_ctx,
                                      pkt->msg, sizeof(pkt->msg));
        if (ret < 0) {
            continue;
        }

        pkt->off = 0;
        pkt->total_len = ret;

        fw_packet_queue_entry_add(fw_if_ptr->pkt_q, pkt);

        os_mutex_lock(&fw_if_ptr->pkt_rx_evt_lock);
        os_cond_signal(&fw_if_ptr->pkt_rx_evt_cond);
        os_mutex_unlock(&fw_if_ptr->pkt_rx_evt_lock);
    }

    return NULL;
}

/* Initialize firewall instance for each interface. */
STATIC int fw_init_all_interfaces(struct firewall_context *fw_ctx)
{
    uint32_t i;

    /* Register network driver callbacks. */
    nw_driver_register(&fw_ctx->nw_drv);

    fw_ctx->n_intf = fw_ctx->args.n_iflist;

    /* Initialize each interface. */
    for (i = 0; i < fw_ctx->args.n_iflist; i ++) {
        fw_ctx->if_list[i].raw_ctx = fw_ctx->nw_drv.init(
                                fw_ctx->args.if_list[i]);
        if (!fw_ctx->if_list[i].raw_ctx) {
            return -1;
        }

        fw_ctx->if_list[i].nw_drv = &fw_ctx->nw_drv;

        /* Create receive thread to read packets. */
        fw_ctx->if_list[i].rx_thr = os_thread_create(MAX_THR_PRIO,
                                                     0,
                                                     &fw_ctx->if_list[i],
                                                     true,
                                                     fw_recv_packet);
        if (!fw_ctx->if_list[i].rx_thr) {
            return -1;
        }

        /* Create processing thread to process the packets. */
        fw_ctx->if_list[i].process_thr = os_thread_create(MAX_THR_PRIO,
                                                          0,
                                                          &fw_ctx->if_list[i],
                                                          true,
                                                          fw_process_packet);
        if (!fw_ctx->if_list[i].process_thr) {
            return -1;
        }

        /* Initialize the packet queue. */
        fw_ctx->if_list[i].pkt_q = fw_packet_queue_init();
        if (!fw_ctx->if_list[i].pkt_q) {
            return -1;
        }

        os_mutex_create(&fw_ctx->if_list[i].pkt_rx_evt_lock);
        os_cond_create(&fw_ctx->if_list[i].pkt_rx_evt_cond);
    }

    return 0;
}

/* Deinitialize firewall instance for each interface. */
STATIC void fw_deinit_all_interfaces(struct firewall_context *fw_ctx)
{
    uint32_t i;

    /* deInitialize each interface. */
    for (i = 0; i < fw_ctx->args.n_iflist; i ++) {
        fw_ctx->nw_drv.deinit(fw_ctx->if_list[i].raw_ctx);
    }
}

int main(int argc, char **argv)
{
    struct firewall_context *fw_ctx;
    int ret;

    fw_debug(FW_DEBUG_LEVEL_INFO, "starting Firewall Daemon\n");

    fw_ctx = calloc(1, sizeof(struct firewall_context));
    if (!fw_ctx) {
        return -1;
    }

    ret = parse_command_args(argc, argv, fw_ctx);
    if (ret < 0) {
        goto free_fw_ctx;
    }

    ret = fw_init_all_interfaces(fw_ctx);
    if (ret < 0) {
        goto deinit_fw;
    }

    while (1) {
        sleep(1);
    }

    return 0;

deinit_fw:
    fw_deinit_all_interfaces(fw_ctx);

free_fw_ctx:
    free(fw_ctx);

    return -1;
}

