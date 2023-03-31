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

struct fw_event_context {
    fw_event_t *evt_head;
    fw_event_t *evt_tail;

    os_mutex_t event_lock;

    int fd;
    struct fw_event_config *evt_config;
    struct sockaddr_in udp_server_addr;

    void *transmit_thread;
};

typedef struct fw_event_context fw_event_context_t;

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

    fw_debug(FW_DEBUG_LEVEL_INFO, "send %d bytes\n", pkt_len);
    return evt_sender_list[evt_transport_type].send(evt_ctx, pkt, pkt_len);
}

STATIC void fw_event_connection_deinit(fw_event_context_t *evt_ctx)
{
    fw_event_transport_type_t evt_transport_type;
    evt_transport_type = evt_ctx->evt_config->evt_transport_type;

    return evt_sender_list[evt_transport_type].deinit(evt_ctx);
}

STATIC void * fw_event_transmit_thread(void *evt_ptr)
{
    struct fw_event_context *evt_ctx = evt_ptr;

    while (1) {
        fw_event_t *event_node;
        fw_event_t *tmp;
        uint32_t pkt_len;

        os_wait_for_timeout(FW_EVENT_TRANSMIT_THREAD_TIMEO_MS);

        /* Initialize connection to the Event server. */
        fw_event_connection_init(evt_ctx);

        os_mutex_lock(&evt_ctx->event_lock);
        {
            event_node = evt_ctx->evt_head;
            while (event_node) {
                uint8_t tx_buf[4096];

                fw_debug(FW_DEBUG_LEVEL_INFO, "read event \n");
                /*
                 * For each node prepre and send the
                 * events in serialized manner.
                 */
                fw_event_fmt_binary_t *bin = (fw_event_fmt_binary_t *)tx_buf;

                pkt_len = fw_event_fmt_binary_serialize(event_node, bin);
                fw_event_connection_send(evt_ctx, tx_buf, pkt_len);

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

void *fw_events_init(struct fw_event_config *evt_config)
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

    return ctx;

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

        free(ctx);
    }
}

