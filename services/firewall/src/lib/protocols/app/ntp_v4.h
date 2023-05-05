#ifndef __LIB_PROTOCOLS_NTP_V4_H__
#define __LIB_PROTOCOLS_NTP_V4_H__

#include <stdint.h>

#define NTP_VERSION_4 4

struct ntpv4_header {
    uint8_t leap_indicator;
    uint8_t version_number;
    uint8_t mode;
    uint8_t peer_clock_stratum;
    uint8_t peer_polling_interval;
    uint8_t peer_clock_precision;
    uint32_t root_delay_sec;
    uint32_t root_dispersion_sec;
    uint32_t reference_id;
    uint64_t reference_timestamp;
    uint64_t origin_timestamp;
    uint64_t receive_timestamp;
    uint64_t transmit_timestamp;
    uint32_t key_id;
    uint8_t mac[16];
};

typedef struct ntpv4_header ntpv4_header_t;

#endif

