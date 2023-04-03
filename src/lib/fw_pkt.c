/**
 * @brief - Implements Packet queue.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <stdint.h>
#include <stdlib.h>
#include <fw_pkt.h>
#include <os_thread.h>

struct fw_packet_queue_context {
    struct fw_packet *head;
    struct fw_packet *tail;
};

typedef struct fw_packet_queue_context fw_packet_queue_context_t;

void *fw_packet_queue_init()
{
    struct fw_packet_queue_context *ctx;

    ctx = calloc(1, sizeof(fw_packet_queue_context_t));
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

    while (entry) {
        t = entry;
        entry = entry->next;
        free(t);
    }

    free(ctx);
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

void fw_hexdump(const char *msg, uint8_t *pkt, uint32_t pkt_len)
{
    uint32_t i;

    fprintf(stderr, "%s: \n", msg);
    for (i = 0; i < pkt_len; i ++) {
        if ((i != 0) && (i % 8) == 0) {
            fprintf(stderr, "  ");
        }
        if ((i != 0) && (i % 16) == 0) {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "%02x ", pkt[i]);
    }
    fprintf(stderr, "\n");
}

uint16_t fw_packet_get_ethertype(fw_packet_t *pkt)
{
    uint16_t ethertype = pkt->eh.ethertype;

    if (ethertype == FW_ETHERTYPE_VLAN) {
        ethertype = pkt->vlan_h.ethertype;
    }

    return ethertype;
}

uint16_t fw_packet_get_vid(fw_packet_t *pkt)
{
    if (pkt->eh.ethertype == FW_ETHERTYPE_VLAN) {
        return pkt->vlan_h.vid;
    }

    return 0;
}

uint32_t fw_packet_get_remaining_len(fw_packet_t *pkt)
{
    int remaining_len = pkt->total_len - pkt->off;

    return (remaining_len < 0) ? 0 : remaining_len;
}

