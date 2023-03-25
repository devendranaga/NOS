#include <stdint.h>
#include <stdbool.h>
#include <os_thread.h>

#define FW_PACKET_LEN_MAX 8192

/* Define firewall packet. */
struct fw_packet {
    uint8_t msg[FW_PACKET_LEN_MAX];
    uint32_t total_len;
    uint32_t off;
    struct os_mutex lock;
    struct fw_packet *next;
};

void *fw_packet_queue_init();
void fw_packet_queue_deinit(void *);
void fw_packet_queue_entry_add(void *q, struct fw_packet *pkt);
struct fw_packet *fw_packet_queue_first(void *q);
