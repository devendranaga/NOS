#ifndef __NOS_PACKET_IEEE8021AE_H__
#define __NOS_PACKET_IEEE8021AE_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>

namespace nos::firewall
{

struct ieee8021ae_tci {
    uint8_t version:1;
    uint8_t es:1;
    uint8_t sc:1;
    uint8_t scb:1;
    uint8_t e:1;
    uint8_t c:1;
    uint8_t an:2;
} __attribute__ ((__packed__));

struct ieee8021ae_sci {
    uint8_t mac[6];
    uint16_t port_id;
};

struct ieee8021ae_header {
#define MACSEC_ICV_LEN 16
    ieee8021ae_tci  tci;
    uint8_t         short_len;
    uint32_t        pkt_no;
    ieee8021ae_sci  sci;
    uint8_t         icv[MACSEC_ICV_LEN];
    uint16_t        ethertype;

    bool is_secured() { return tci.e && tci.c; }
    event_type deserialize(packet_buf &buf);
    void print();
    void free_hdr() { }
};

}

#endif
