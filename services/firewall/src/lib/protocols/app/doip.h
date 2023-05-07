#ifndef __NOS_DOIP_HEADER_H__
#define __NOS_DOIP_HEADER_H__

#include <stdint.h>

typedef enum nos_doip_resp {
    NOS_DOIP_GEN_DOIP_NACK              = 0x0000,
    NOS_DOIP_VEH_ID_REQ                 = 0x0001,
    NOS_DOIP_RESP_VEH_ID_RESP           = 0x0004,
    NOS_DOIP_ROUTING_ACTIVATION_REQ     = 0x0005,
    Nos_DOIP_ROUTING_ACTIVATION_RESP    = 0x0006,
    NOS_DOIP_ALIVE_CHECK_REQ            = 0x0007,
    NOS_DOIP_ALIVE_CHECK_RESP           = 0x0008,
    NOS_DOIP_ENTITY_STATUS_REQ          = 0x4001,
    NOS_DOIP_ENTITY_STATUS_RESP         = 0x4002,
    NOS_DOIP_DIAG_POWER_MODE_INFO_REQ   = 0x4003,
    NOS_DOIP_DIAG_POWER_MODE_INFO_RESP  = 0x4004,
    NOS_DOIP_DIAG_MESSAGE               = 0x8001,
    NOS_DOIP_DIAG_MESSAGE_ACK           = 0x8002,
} nos_doip_resp_t;

typedef struct nos_doip_veh_id_resp {
    uint8_t vin[17];
    uint16_t logical_address;
    uint8_t eid[6];
    uint8_t gid[6];
    uint8_t further_action;
} nos_doip_veh_id_resp_t;

typedef enum nos_doip_node_type {
    NOS_DOIP_NODE_TYPE_GATEWAY,
} nos_doip_node_type_t;

typedef struct nos_doip_entity_status_resp {
    uint8_t node_type;
    uint8_t max_concurrent_sockets;
    uint8_t currently_open_sockets;
    uint32_t max_data_size;
} nos_doip_entity_status_resp_t;

typedef struct nos_doip_routing_activation_req {
    uint16_t source_addr;
    uint8_t activation_type;
    uint32_t reserved_by_iso;
    uint32_t reserved_by_oem;
} nos_doip_routing_activation_req_t;

typedef enum nos_routing_activation_resp_code {
    NOS_DOIP_ROUTING_ACTIV_RESP_CODE_SUCCESS = 0x10,
} nos_routing_activation_resp_code_t;

typedef struct nos_doip_routing_activation_resp {
    uint16_t tester_addr;
    uint16_t source_addr;
    uint8_t resp_code;
    uint32_t reserved_by_iso;
} nos_doip_routing_activation_resp_t;

typedef enum nos_doip_nack_type {
    DOIP_NACK_UNKNOWN_PAYLOAD_TYPE = 0x01,
} nos_doip_nack_type_t;

typedef struct nos_doip_header_nack {
    uint8_t value;
} nos_doip_header_nack_t;

typedef struct nos_doip_alive_check_resp {
    uint16_t source_addr;
} nos_doip_alive_check_resp_t;

typedef struct nos_diag_power_mode_info_resp {
    uint8_t power_mode;
} nos_diag_power_mode_info_resp_t;

typedef struct nos_uds_diag_sess_control {
    uint8_t type;
} nos_uds_diag_sess_control_t;

typedef struct nos_uds_diag_session_control_ack {
    uint8_t type;
    uint32_t parameter_record;
} nos_uds_diag_session_control_ack_t;

typedef struct nos_uds_diag_service_id_error {
    uint8_t service_id;
    uint8_t code;
} nos_uds_diag_service_id_error_t;

typedef struct nos_diag_uds {
    uint8_t service_id;
    bool is_reply;

    nos_uds_diag_sess_control_t             sess_control;
    nos_uds_diag_session_control_ack_t      sess_control_ack;
    nos_uds_diag_service_id_error_t         error;
} nos_diag_uds_t;

typedef struct nos_diag_uds_ack {
    uint16_t source_addr;
    uint16_t target_addr;
    uint8_t ack_code;
} nos_diag_uds_ack_t;

typedef struct nos_doip_header {
    uint8_t version;
    uint8_t inv_version;
    uint16_t type;
    uint32_t len;

    nos_doip_veh_id_resp_t              *veh_id_resp;
    nos_doip_routing_activation_req_t   *route_activ_req;
    nos_doip_routing_activation_resp_t  *route_activ_resp;
    nos_doip_entity_status_resp_t       *status_resp;
    nos_doip_header_nack_t              *nack;
    nos_doip_alive_check_resp_t         *alive_chk_resp;
    nos_diag_power_mode_info_resp_t     *power_mode_resp;
    nos_diag_uds_t                      *diag_uds;
    nos_diag_uds_ack_t                  *diag_uds_ack;
} nos_doip_header_t;

#endif

