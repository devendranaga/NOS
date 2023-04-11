/**
 * @brief - Implements eventing mechanism.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <events.h>

/* Event Transmit Thread Priority. */
#define FW_EVENT_TRANSMIT_THREAD_PRIO       10

/* Event Transmit Thread timeout. */
#define FW_EVENT_TRANSMIT_THREAD_TIMEO_MS   1000

/* Event Context. */
struct fw_event_context {
    fw_event_t *evt_head;
    fw_event_t *evt_tail;

    os_mutex_t event_lock;

    /* Event fd UDP / TCP / MQTT. */
    int fd;

    FILE *log_fp;
    struct fw_event_config *evt_config;
    struct sockaddr_in udp_server_addr;

    void *transmit_thread;
};

typedef struct fw_event_context fw_event_context_t;

/**
 * Event ID to Rule ID mappings for signatures that
 * are found directly within the Firewall.
 */
STATIC CONST struct fw_event_rule_id_base {
    fw_event_details_t event_details;
    uint32_t rule_id;
} fw_event_rule_id_list[] = {
    {FW_EVENT_DESCR_ETH_SRC_DST_ARE_BROADCAST,      0x00000001U},
    {FW_EVENT_DESCR_ETH_SRC_DST_ARE_ZERO,           0x00000002U},
    {FW_EVENT_DESCR_ETH_UNSPPORTED_ETHERTYPE,       0x00000003U},
    {FW_EVENT_DESCR_ARP_HWTYPE_INVAL,               0x00000004U},
    {FW_EVENT_DESCR_ARP_HDR_LEN_TOO_SHORT,          0x00000005U},
    {FW_EVENT_DESCR_ARP_INVAL_HWADDR_LEN,           0x00000006U},
    {FW_EVENT_DESCR_ARP_INVAL_PROTO_ADDR_LEN,       0x00000007U},
    {FW_EVENT_DESCR_ARP_OP_INVAL,                   0x00000008U},
    {FW_EVENT_DESCR_IPV4_INVAL_VERSION,             0x00000009U},
    {FW_EVENT_DESCR_IPV4_HDR_LEN_TOO_SMALL,         0x0000000AU},
    {FW_EVENT_DESCR_IPV4_FLAGS_RESERVED_SET,        0x0000000BU},
    {FW_EVENT_DESCR_IPV4_FLAGS_BOTH_MF_DF_SET,      0x0000000CU},
    {FW_EVENT_DESCR_IPV4_TTL_ZERO,                  0x0000000DU},
    {FW_EVENT_DESCR_IEEE8021AE_HDRLEN_TOO_SMALL,    0x0000000EU},
    {FW_EVENT_DESCR_IPV4_UNSUPPORTED_PROTOCOL,      0x0000000FU},
    {FW_EVENT_DESCR_ICMP_INVAL,                     0000000010U},
    {FW_EVENT_DESCR_ICMP_UNSUPPORTED_TYPE,          0x00000011U},
    {FW_EVENT_DESCR_ICMP_HDR_TOO_SMALL,             0x00000012U},
    {FW_EVENT_DESCR_TCP_HDR_FLAGS_NULL,             0x00000013U},
    {FW_EVENT_DESCR_TCP_RESERVED_FLAGS_SET,         0x00000014U},
    {FW_EVENT_DESCR_TCP_SRC_PORT_ZERO,              0x00000015U},
    {FW_EVENT_DESCR_TCP_DST_PORT_ZERO,              0x00000016U},
    {FW_EVENT_DESCR_TCP_SYN_FIN_BOTH_SET,           0x00000017U},
    {FW_EVENT_DESCR_TCP_ALL_FLAGS_SET,              0x00000018U},
    {FW_EVENT_DESCR_UDP_SRC_PORT_ZERO,              0x00000019U},
    {FW_EVENT_DESCR_UDP_DST_PORT_ZERO,              0x0000001AU},
    {FW_EVENT_DESCR_UDP_PAYLOAD_LEN_ZERO,           0x0000001BU},
    {FW_EVENT_DESCR_IPV6_HDRLEN_TOO_SMALL,          0x0000001CU},
    {FW_EVENT_DESCR_ICMP6_HDRLEN_TOO_SMALL,         0x0000001DU},
    {FW_EVENT_DESCR_ICMP6_UNSUPPORTED_TYPE,         0x0000001EU},
};

/**
 * @brief - Initialize UDP connection to the event server.
 *
 * @param [in] evt_ctx - Event Context.
 *
 * @return 0 on success -1 on failure.
 */
STATIC int fw_event_connection_udp_init(fw_event_context_t *evt_ctx)
{
    struct sockaddr_in *server_addr =  &evt_ctx->udp_server_addr;
    const char *ipaddr = evt_ctx->evt_config->ip;
    int port = evt_ctx->evt_config->port;
    int ret = -1;

    evt_ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (evt_ctx->fd > 0) {
        server_addr->sin_addr.s_addr = inet_addr(ipaddr);
        server_addr->sin_port = htons(port);
        server_addr->sin_family = AF_INET;
        ret = 0;
    }

    return ret;
}

STATIC int fw_event_connection_udp_send(fw_event_context_t *ctx,
                                        CONST uint8_t *data,
                                        uint32_t data_len)
{
    return sendto(ctx->fd, data, data_len, 0,
                  (struct sockaddr *)&ctx->udp_server_addr,
                  sizeof(struct sockaddr_in));
}

STATIC void fw_event_connection_udp_deinit(fw_event_context_t *ctx)
{
    if (ctx->fd > 0) {
        close(ctx->fd);
    }
}

/**
 * @brief - Sender callbacks.
 */
struct fw_event_sender {
    int (*init)(fw_event_context_t *evt_cx);
    int (*send)(fw_event_context_t *evt_ctx,
                CONST uint8_t *pkt, uint32_t pkt_len);
    void (*deinit)(fw_event_context_t *evt_ctx);
} evt_sender_list[] = {
    {
        fw_event_connection_udp_init,
        fw_event_connection_udp_send,
        fw_event_connection_udp_deinit,
    }
};

STATIC int fw_event_connection_init(fw_event_context_t *evt_ctx)
{
    fw_event_transport_type_t evt_transport_type;
    evt_transport_type = evt_ctx->evt_config->evt_transport_type;

    return evt_sender_list[evt_transport_type].init(evt_ctx);
}

STATIC int fw_event_connection_send(fw_event_context_t *evt_ctx,
                                    CONST uint8_t *pkt, uint32_t pkt_len)
{
    fw_event_transport_type_t evt_transport_type;
    evt_transport_type = evt_ctx->evt_config->evt_transport_type;

    return evt_sender_list[evt_transport_type].send(evt_ctx, pkt, pkt_len);
}

STATIC void fw_event_connection_deinit(fw_event_context_t *evt_ctx)
{
    fw_event_transport_type_t evt_transport_type;
    evt_transport_type = evt_ctx->evt_config->evt_transport_type;

    return evt_sender_list[evt_transport_type].deinit(evt_ctx);
}

STATIC int fw_event_serializer_binary(fw_event_context_t *evt_ctx,
                                      fw_event_t *evt)
{
    uint8_t tx_buf[4096];
    uint32_t pkt_len;

    /*
     * For each node prepre and send the
     * events in serialized manner.
     */
    fw_event_fmt_binary_t *bin = (fw_event_fmt_binary_t *)tx_buf;

    pkt_len = fw_event_fmt_binary_serialize(evt, bin);
    return fw_event_connection_send(evt_ctx, tx_buf, pkt_len);
}

STATIC int fw_event_write_log(fw_event_context_t *evt_ctx,
                              fw_event_t *evt)
{
    fprintf(evt_ctx->log_fp, "%u, 0x%04x, %u, '' \n",
                            evt->rule_id,
                            evt->protocol_event.ethertype,
                            evt->protocol_event.vid);
    return 0;
}

struct fw_event_serializer {
    int (*serializer)(fw_event_context_t *evt_ctx,
                      fw_event_t *evt);
} fw_event_serializer_list[] = {
    {
        fw_event_serializer_binary,
    },
    {
        fw_event_write_log,
    },
};

STATIC void * fw_event_transmit_thread(void *evt_ptr)
{
    struct fw_event_context *evt_ctx = evt_ptr;
    fw_event_format_type_t evt_fmt;

    evt_fmt = evt_ctx->evt_config->evt_format_type;

    while (1) {
        fw_event_t *event_node;
        fw_event_t *tmp;

        os_wait_for_timeout(FW_EVENT_TRANSMIT_THREAD_TIMEO_MS);

        /* Initialize connection to the Event server. */
        fw_event_connection_init(evt_ctx);

        os_mutex_lock(&evt_ctx->event_lock);
        {
            event_node = evt_ctx->evt_head;
            while (event_node) {
                fw_event_serializer_list[evt_fmt].serializer(evt_ctx,
                                                         event_node);

                tmp = event_node;
                event_node = event_node->next;
                free(tmp);
            }

            evt_ctx->evt_head = NULL;
            evt_ctx->evt_tail = NULL;
        }
        os_mutex_unlock(&evt_ctx->event_lock);

        fw_event_connection_deinit(evt_ctx);
    }

    return NULL;
}

void *fw_events_init(fw_event_config_t *evt_config)
{
    fw_event_context_t *ctx;

    ctx = calloc(1, sizeof(fw_event_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->evt_config = evt_config;

    /* Create a Transmit Thread for the Events. */
    ctx->transmit_thread = os_thread_create(FW_EVENT_TRANSMIT_THREAD_PRIO,
                                            1,
                                            ctx,
                                            true,
                                            fw_event_transmit_thread);
    if (!ctx->transmit_thread) {
        goto free_ctx;
    }

    ctx->evt_head = NULL;
    ctx->evt_tail = NULL;

    if (evt_config->log_to_file) {
        /* Create Event Logging Thread. */
        ctx->log_fp = fopen(evt_config->event_log_file, "w");
        if (!ctx->log_fp) {
            goto free_thread;
        }

        fprintf(ctx->log_fp, "Rule_ID, Ethertype, VLAN ID, Message\n");
        fflush(ctx->log_fp);
    }

    return ctx;

free_thread:
    os_thread_destroy(ctx->transmit_thread);

free_ctx:
    if (ctx) {
        free(ctx);
    }

    return NULL;
}

fw_event_t *fw_event_new(fw_event_type_t event,
                         fw_event_details_t event_details)
{
    fw_event_t *evt = calloc(1, sizeof(fw_event_t));
    if (!evt) {
        return NULL;
    }

    evt->event = event;
    evt->event_details = event_details;
    evt->protocol_event.protocol = FW_EVENT_PROTOCOL_NONE;

    return evt;
}

void fw_event_free(fw_event_t *evt)
{
    if (evt) {
        free(evt);
    }
}

void fw_event_add(void *evt_ptr, fw_event_t *evt)
{
    fw_event_context_t *ctx = evt_ptr;

    os_mutex_lock(&ctx->event_lock);
    if (!ctx->evt_head) {
        ctx->evt_head = evt;
        ctx->evt_tail = evt;
    } else {
        ctx->evt_tail->next = evt;
        ctx->evt_tail = evt;
    }
    os_mutex_unlock(&ctx->event_lock);
}

void fw_events_deinit(void *evt_ptr)
{
    fw_event_context_t *ctx = evt_ptr;
    fw_event_t *evt = ctx->evt_head;
    fw_event_t *tmp = evt;

    if (ctx) {
        os_mutex_lock(&ctx->event_lock);
        while (evt != NULL) {
            tmp = evt;
            evt = evt->next;
            free(tmp);
        }
        os_mutex_unlock(&ctx->event_lock);

        if (ctx->log_fp) {
            fflush(ctx->log_fp);
            fclose(ctx->log_fp);
        }
        free(ctx);
    }
}

uint32_t fw_event_get_rule_id_on_event_descr(fw_event_details_t evt_descr)
{
    uint32_t i;

    for (i = 0; i < SIZEOF(fw_event_rule_id_list); i ++) {
        if (evt_descr == fw_event_rule_id_list[i].event_details) {
            return fw_event_rule_id_list[i].rule_id;
        }
    }

    return 0;
}

