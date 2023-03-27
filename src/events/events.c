/**
 * @brief - Implements eventing mechanism.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <events.h>

#define FW_EVENT_TRANSMIT_THREAD_PRIO       10
#define FW_EVENT_TRANSMIT_THREAD_TIMEO_MS   1000

struct fw_event_context {
    fw_event_t *evt_head;
    fw_event_t *evt_tail;

    void *transmit_thread;
};

typedef struct fw_event_context fw_event_context_t;

STATIC void * fw_event_transmit_thread()
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

    ctx->transmit_thread = os_thread_create(FW_EVENT_TRANSMIT_THREAD_PRIO,
                                            1,
                                            ctx,
                                            true,
                                            fw_event_transmit_thread);
    if (!ctx->transmit_thread) {
        goto free_ctx;
    }

free_ctx:
    if (ctx) {
        free(ctx);
    }
}

void fw_event_add(void *evt_ptr, fw_event_t *evt)
{
}

