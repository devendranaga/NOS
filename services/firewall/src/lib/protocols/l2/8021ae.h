#ifndef __LIB_PROTOCOLS_8021AE_H__
#define __LIB_PROTOCOLS_8021AE_H__

#include <stdint.h>
#include <stdbool.h>

#define IEEE8021AE_SCI_LEN 6
#define IEEE8021AE_ICV_LEN 16

struct ieee8021ae_hdr {
    uint8_t sectag;
    bool ver;
    bool es;
    bool sc;
    bool scb;
    bool e;
    bool c;
    uint8_t an;
    uint8_t short_len;
    uint32_t packet_no;
    uint8_t sci[IEEE8021AE_SCI_LEN];
    uint16_t port_id;
    uint8_t icv[IEEE8021AE_ICV_LEN];
    uint16_t pkt_len;
};

typedef struct ieee8021ae_hdr ieee8021ae_hdr_t;

bool ieee8021ae_has_encrypt_on(ieee8021ae_hdr_t *hdr);

#endif
