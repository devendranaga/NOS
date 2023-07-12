/**
 * @brief - Implements MQTT parsing.
 *
 * @author Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <packet.h>

namespace nos::firewall
{

event_type mqtt_connect_header::deserialize(packet_buf &buf,
                                            const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_2_bytes(&protocol_name_len);
    buf.deserialize_bytes(protocol_name, protocol_name_len);
    buf.deserialize_byte(&version);

    flags.username_flag = !!(buf.data[buf.off] & 0x80);
    flags.password_flag = !!(buf.data[buf.off] & 0x40);
    flags.will_retain = !!(buf.data[buf.off] & 0x20);
    flags.qos_level = (buf.data[buf.off] & 0x18) >> 3;
    flags.will = !!(buf.data[buf.off] & 0x04);
    flags.clean_session = !!(buf.data[buf.off] & 0x02);
    flags.reserved = !!(buf.data[buf.off] & 0x01);

    buf.off ++;

    buf.deserialize_2_bytes(&keep_alive);
    buf.deserialize_2_bytes(&client_id_len);
    buf.deserialize_bytes(client_id, client_id_len);

    return event_type::NO_ERROR;
}

event_type mqtt_connect_ack_header::deserialize(packet_buf &buf,
                                                const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_byte(&reserved);
    buf.deserialize_byte(&return_code);

    return event_type::NO_ERROR;
}

event_type mqtt_sub_req_header::deserialize(packet_buf &buf,
                                            const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_2_bytes(&msg_id);
    buf.deserialize_2_bytes(&topic_len);
    if (topic_len > 0) {
        buf.deserialize_bytes(topic, topic_len);
    }
    buf.deserialize_byte(&req_qos);

    return event_type::NO_ERROR;
}

event_type mqtt_sub_ack_header::deserialize(packet_buf &buf,
                                            const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_2_bytes(&msg_id);
    buf.deserialize_byte(&granted_qos);

    return event_type::NO_ERROR;
}

event_type mqtt_publish_msg_header::deserialize(packet_buf &buf,
                                                const std::shared_ptr<nos::core::logging> &log)
{
    uint16_t remaining_bytes;

    buf.deserialize_2_bytes(&topic_len);
    if (topic_len > 0) {
        buf.deserialize_bytes(topic, topic_len);
    }

    remaining_bytes = buf.remaining_bytes();
    buf.deserialize_bytes(msg, remaining_bytes);

    return event_type::NO_ERROR;
}

event_type mqtt_ping_req_header::deserialize(packet_buf &buf,
                                             const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_byte((uint8_t *)&msg_len);

    return event_type::NO_ERROR;
}

event_type mqtt_ping_resp_header::deserialize(packet_buf &buf,
                                              const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_byte((uint8_t *)&msg_len);

    return event_type::NO_ERROR;
}

event_type mqtt_disconn_req_header::deserialize(packet_buf &buf,
                                                const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_byte((uint8_t *)&msg_len);

    return event_type::NO_ERROR;
}

event_type mqtt_header::deserialize(packet_buf &buf,
                                    const std::shared_ptr<nos::core::logging> &log)
{
    event_type type = event_type::MQTT_UKNOWN_MSG_TYPE;

    msg_type = (buf.data[buf.off] & 0xF0) >> 4;
    reserved = buf.data[buf.off] & 0x0F;
    /* TODO: Fix message length decode. */
    buf.deserialize_byte((uint8_t *)&msg_len);

    switch (msg_type) {
        case MQTT_MSG_TYPE_CONNECT:
            type = connect_hdr.deserialize(buf, log);
        break;
        case MQTT_MSG_TYPE_CONNECT_ACK:
            type = connect_ack_hdr.deserialize(buf, log);
        break;
        case MQTT_MSG_TYPE_SUB_REQ:
            type = sub_req_hdr.deserialize(buf, log);
        break;
        case MQTT_MSG_TYPE_SUB_ACK:
            type = sub_ack_hdr.deserialize(buf, log);
        break;
        case MQTT_MSG_TYPE_PUBLISH:
            type = pub_msg.deserialize(buf, log);
        break;
        case MQTT_MSG_TYPE_PING_REQ:
            type = ping_req.deserialize(buf, log);
        break;
        case MQTT_MSG_TYPE_PING_RESP:
            type = ping_resp.deserialize(buf, log);
        break;
        case MQTT_MSG_TYPE_DISCONN_REQ:
            type = disconn_req.deserialize(buf, log);
        break;
        default:
            return event_type::MQTT_UKNOWN_MSG_TYPE;
    }

    return type;
}

}
