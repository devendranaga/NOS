/**
 * @brief - Implements Firewall daemon.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <firewall.h>

#define MAX_THR_PRIO 1

CONST uint32_t term_signals[] = {SIGINT, SIGTERM};
STATIC bool term_signal = false;

/* Queue the received event. */
STATIC void fw_queue_event(firewall_interface_context_t *fw_if_ctx,
                           fw_packet_t *pkt,
                           fw_event_details_t evt_descr)
{
    fw_event_type_t evt_type;
    uint32_t rule_id;
    fw_event_t *evt;

    rule_id = fw_event_get_rule_id_on_event_descr(evt_descr);

    FW_EVENT_GET_TYPE(evt_type, evt_descr);

    /* Queue the event. */
    evt = fw_event_new(evt_type, evt_descr);
    if (evt) {
        strcpy(evt->ifname, fw_if_ctx->ifname);
        if (rule_id == 0) {
            evt->rule_id = pkt->matched_rule_id;
        } else {
            evt->rule_id = rule_id;
        }
        evt->protocol_event.ethertype = fw_packet_get_ethertype(pkt);
        evt->protocol_event.vid = fw_packet_get_vid(pkt);
        fw_event_add(fw_if_ctx->evt_ctx, evt);
    }
}

/*
 * Process received packet.
 *  - Parse the packet.
 *  - Run the filter.
 *  - Queue the events to the Event Thread.
 */
STATIC void * fw_process_packet(void *usr_ptr)
{
    struct firewall_interface_context *fw_if_ptr = usr_ptr;
    fw_packet_t *pkt;

    /* delay a bit to let the rx thread schedule first. */
    os_wait_for_timeout(1000);

    while (1) {
        os_mutex_lock(&fw_if_ptr->pkt_rx_evt_lock);
        os_cond_wait(&fw_if_ptr->pkt_rx_evt_cond, &fw_if_ptr->pkt_rx_evt_lock);
        while (1) {
            fw_event_details_t evt_descr;

            /* Retrieve first entry in the queue. */
            pkt = fw_packet_queue_first(fw_if_ptr->pkt_q);
            if (pkt == NULL) {
                break;
            }

            fw_debug(FW_DEBUG_LEVEL_INFO, "parse rx msg of len [%d]\n",
                                                    pkt->total_len);
            /* Parse the protocol. */
            evt_descr = parse_protocol(pkt);

            /* Queue the generated event. */
            fw_queue_event(fw_if_ptr, pkt, evt_descr);

            free(pkt);
        }
        os_mutex_unlock(&fw_if_ptr->pkt_rx_evt_lock);
    }

    return NULL;
}

/*
 * Receive thread:
 *  - receive the packet from the raw socket.
 *  - queue the packet to the processing thread.
 */
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

        /* Read a packet from the interface. */
        ret = fw_if_ptr->nw_drv->read(fw_if_ptr->raw_ctx,
                                      pkt->msg, sizeof(pkt->msg));
        if (ret < 0) {
            continue;
        }

        fw_debug(FW_DEBUG_LEVEL_INFO, "read packet of length %d\n", ret);
        pkt->off = 0;
        pkt->total_len = ret;

        fw_if_ptr->stats.n_rx ++;

        /* Queue the packet to the processing engine. */
        os_mutex_lock(&fw_if_ptr->pkt_rx_evt_lock);
        fw_packet_queue_entry_add(fw_if_ptr->pkt_q, pkt);
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

        /* Copy interface name. */
        strcpy(fw_ctx->if_list[i].ifname, fw_ctx->args.if_list[i]);

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

        /* Initialize event context. */
        fw_ctx->if_list[i].evt_ctx = fw_events_init(&fw_ctx->args.event_config);
        if (!fw_ctx->if_list[i].evt_ctx) {
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
        fw_events_deinit(fw_ctx->if_list[i].evt_ctx);

        /* Deinitialize packet queue. */
        fw_packet_queue_deinit(fw_ctx->if_list[i].pkt_q);

        /* Deinitialize the network driver. */
        fw_ctx->nw_drv.deinit(fw_ctx->if_list[i].raw_ctx);

        /* Deinitialize all the threads. */
        os_thread_destroy(fw_ctx->if_list[i].rx_thr);
        os_thread_destroy(fw_ctx->if_list[i].process_thr);
    }
}

STATIC void fw_signal_handler(int signum)
{
    term_signal = true;
}

int main(int argc, char **argv)
{
    struct firewall_context *fw_ctx;
    int ret;

    fw_debug(FW_DEBUG_LEVEL_INFO, "Starting Firewall Daemon\n");

    fw_ctx = calloc(1, sizeof(struct firewall_context));
    if (!fw_ctx) {
        return -1;
    }

    /* Parse command line arguments. */
    ret = fw_parse_command_args(argc, argv, &fw_ctx->args);
    if (ret < 0) {
        goto free_fw_ctx;
    }

    /* Parse configuration. */
    ret = fw_base_config_parse(fw_ctx->args.config_file,
                               &fw_ctx->base_conf);
    if (ret < 0) {
        goto free_fw_ctx;
    }

    /* Initialize all interfaces. */
    ret = fw_init_all_interfaces(fw_ctx);
    if (ret < 0) {
        goto deinit_fw;
    }

    /* Register termination handlers. */
    os_register_signals(term_signals, SIZEOF(term_signals), fw_signal_handler);

    /* Wait for the termination signal. */
    while (1) {
        os_wait_for_timeout(1000);
        if (term_signal) {
            fw_debug(FW_DEBUG_LEVEL_INFO, "Received term signal\n");
            break;
        }
    }

    /* Deinitialize the firewall daemon. */
    fw_deinit_all_interfaces(fw_ctx);
    free(fw_ctx);

    return 0;

deinit_fw:
    fw_debug(FW_DEBUG_LEVEL_ERROR, "Stopping firewall\n");
    fw_deinit_all_interfaces(fw_ctx);

free_fw_ctx:
    free(fw_ctx);

    return -1;
}

