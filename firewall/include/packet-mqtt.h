/**
 * @brief - Implements MQTT parsing.
 *
 * @author Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_FIREWALL_PACKET_MQTT_H__
#define __NOS_FIREWALL_PACKET_MQTT_H__

#include <stdint.h>
#include <event_types.h>
#include <packet-buf.h>
#include <nos_core.h>

namespace nos::firewall
{

#define MQTT_MSG_TYPE_CONNECT       1
#define MQTT_MSG_TYPE_CONNECT_ACK   2
#define MQTT_MSG_TYPE_PUBLISH       3
#define MQTT_MSG_TYPE_SUB_REQ       8
#define MQTT_MSG_TYPE_SUB_ACK       9
#define MQTT_MSG_TYPE_PING_REQ      12
#define MQTT_MSG_TYPE_PING_RESP     13
#define MQTT_MSG_TYPE_DISCONN_REQ   14

struct mqtt_connect_flags {
    bool username_flag;
    bool password_flag;
    bool will_retain;
    uint8_t qos_level;
    bool will;
    bool clean_session;
    bool reserved;
};

struct mqtt_connect_header {
    uint16_t protocol_name_len;
    uint8_t protocol_name[16];
    uint8_t version;
    mqtt_connect_flags flags;
    uint16_t keep_alive;
    uint16_t client_id_len;
    uint8_t client_id[64];

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_connect_ack_header {
    uint8_t reserved;
    uint8_t return_code;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_sub_req_header {
    uint16_t msg_id;
    uint16_t topic_len;
    uint8_t topic[32];
    uint8_t req_qos;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_sub_ack_header {
    uint16_t msg_id;
    uint8_t granted_qos;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_publish_msg_header {
    uint16_t topic_len;
    uint8_t topic[32];
    uint8_t msg[1024];

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_ping_req_header {
    uint8_t msg_len;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_ping_resp_header {
    uint8_t msg_len;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_disconn_req_header {
    uint8_t msg_len;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_header {
    uint8_t msg_type;
    uint8_t reserved;
    uint32_t msg_len;
    mqtt_connect_header connect_hdr;
    mqtt_connect_ack_header connect_ack_hdr;
    mqtt_sub_req_header sub_req_hdr;
    mqtt_sub_ack_header sub_ack_hdr;
    mqtt_publish_msg_header pub_msg;
    mqtt_ping_req_header ping_req;
    mqtt_ping_resp_header ping_resp;
    mqtt_disconn_req_header disconn_req;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

}

#endif
