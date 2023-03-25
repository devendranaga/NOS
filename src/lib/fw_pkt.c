#include <stdint.h>
#include <stdlib.h>
#include <fw_pkt.h>
#include <os_thread.h>

struct fw_packet_queue_context {
    struct fw_packet *head;
    struct fw_packet *tail;
};

void *fw_packet_queue_init()
{
    struct fw_packet_queue_context *ctx;

    ctx = calloc(1, sizeof(struct fw_packet_queue_context));
    if (!ctx) {
        return NULL;
    }

    return ctx;
}

void fw_packet_queue_entry_add(void *q, struct fw_packet *pkt)
{
    struct fw_packet_queue_context *ctx = q;

    if (!ctx->head) {
        ctx->head = pkt;
        ctx->tail = pkt;
    } else {
        ctx->tail->next = pkt;
        ctx->tail = pkt;
    }
}

void fw_packet_queue_deinit(void *q)
{
    struct fw_packet_queue_context *ctx = q;
    struct fw_packet *entry = ctx->head;
    struct fw_packet *t;

    do {
        t = entry;
        entry = entry->next;
        free(t);
    } while (entry != NULL);
}

struct fw_packet *fw_packet_queue_first(void *q)
{
    struct fw_packet_queue_context *ctx = q;
    struct fw_packet *entry = ctx->head;

    if (ctx->head) {
        ctx->head = ctx->head->next;
        if (ctx->head == NULL) {
            ctx->tail = NULL;
        }
    }

    return entry;
}

