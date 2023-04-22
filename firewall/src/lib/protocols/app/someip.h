#ifndef __LIB_PROTOCOLS_SOMEIP_H__
#define __LIB_PROTOCOLS_SOMEIP_H__

#include <stdint.h>

struct someip_header {
    uint16_t service_id;
    uint16_t method_id;
    uint32_t length;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t version;
    uint8_t interface_version;
    uint8_t message_type;
    uint8_t return_code;
};

typedef struct someip_header someip_header_t;

#endif
