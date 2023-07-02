#include <packet.h>

namespace nos::firewall
{

event_type ntp_v4_header::deserialize(packet_buf &buf,
                                      const std::shared_ptr<nos::core::logging> &log)
{
    leap_indicator = (buf.data[buf.off] & 0xC0) >> 6;
    version = (buf.data[buf.off] & 0x38) >> 3;
    mode = (buf.data[buf.off] & 0x07);
    buf.deserialize_byte(&peer_clock_stratum);
    buf.deserialize_byte(&peer_clock_poll_interval);
    buf.deserialize_byte(&peer_clock_precision);
    buf.deserialize_4_bytes(&root_delay);
    buf.deserialize_4_bytes(&root_dispersion);
    buf.deserialize_4_bytes(&reference_id);
    buf.deserialize_8_bytes(&reference_timestamp);
    buf.deserialize_8_bytes(&origin_timestamp);
    buf.deserialize_8_bytes(&receive_timestamp);
    buf.deserialize_8_bytes(&transmit_timestamp);
    buf.deserialize_4_bytes(&keyid);
    buf.deserialize_bytes(mac, sizeof(mac));

    return event_type::NO_ERROR;
}

}
