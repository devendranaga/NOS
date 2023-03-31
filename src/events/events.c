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

    void *transmit_thread;
};

typedef struct fw_event_context fw_event_context_t;

STATIC void * fw_event_transmit_thread(void *)
{
    while (1) {
        os_wait_for_timeout(FW_EVENT_TRANSMIT_THREAD_TIMEO_MS);
    }

    return NULL;
}

void *fw_events_init()
{
    fw_event_context_t *ctx;

    ctx = calloc(1, sizeof(fw_event_context_t));
    if (!ctx) {
        return NULL;
    }

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

