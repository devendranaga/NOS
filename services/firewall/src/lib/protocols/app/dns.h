#ifndef __LIB_PROTOCOLS_DNS_H__
#define __LIB_PROTOCOLS_DNS_H__

#include <stdint.h>

typedef struct dns_query {
    char name[32];
    uint16_t label_type;
    uint16_t label_class;
} dns_query_t;

typedef struct dns_header {
    uint16_t transaction_id;
    uint8_t flags_response;
    uint8_t flags_opcode;
    uint8_t flags_truncated;
    uint8_t flags_recursion_denied;
    uint8_t flags_z;
    uint8_t flags_non_auth_data;
    uint16_t questions;
    uint16_t answer_rr;
    uint16_t authority_rr;
    uint16_t additional_rr;
    dns_query_t queries[10];
} dns_header_t;

#endif

