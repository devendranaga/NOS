#include <packet.h>

namespace nos::firewall
{

event_type mqtt_connect_header::deserialize(packet_buf &buf,
                                            const std::shared_ptr<nos::core::logging> &log)
{
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

event_type mqtt_header::deserialize(packet_buf &buf,
                                    const std::shared_ptr<nos::core::logging> &log)
{
    event_type type;

    msg_type = (buf.data[buf.off] & 0xF0) >> 4;
    reserved = buf.data[buf.off] & 0x0F;
    /* TODO: Fix message length decode. */
    buf.deserialize_byte((uint8_t *)&msg_len);
    buf.deserialize_2_bytes(&protocol_name_len);
    buf.deserialize_bytes(protocol_name, protocol_name_len);
    buf.deserialize_byte(&version);

    switch (msg_type) {
        case MQTT_MSG_TYPE_CONNECT:
            type = connect_hdr.deserialize(buf, log);
        break;
        default:
            return event_type::MQTT_UKNOWN_MSG_TYPE;
    }

    return type;
}

}
