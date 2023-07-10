#ifndef __NOS_FIREWALL_PACKET_MQTT_H__
#define __NOS_FIREWALL_PACKET_MQTT_H__

#include <stdint.h>
#include <event_types.h>
#include <packet-buf.h>
#include <nos_core.h>

namespace nos::firewall
{

#define MQTT_MSG_TYPE_CONNECT 1

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
    mqtt_connect_flags flags;
    uint16_t keep_alive;
    uint16_t client_id_len;
    uint8_t client_id[64];

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

struct mqtt_header {
    uint8_t msg_type;
    uint8_t reserved;
    uint32_t msg_len;
    uint16_t protocol_name_len;
    uint8_t protocol_name[16];
    uint8_t version;
    mqtt_connect_header connect_hdr;
    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    void free_hdr() { }
};

}

#endif
