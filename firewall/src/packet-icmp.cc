#include <packet-icmp.h>

namespace nos::firewall
{

event_type icmp_redirect::deserialize(packet_buf &buf)
{
    event_type type;

    buf.deserialize_4_bytes(&ipaddr);
    type = ipv4_hdr.deserialize(buf);
    if (type != event_type::NO_ERROR) {
        return type;
    }

    buf.deserialize_bytes(datagram_data, sizeof(datagram_data));

    return event_type::NO_ERROR;
}

event_type icmp_time_exceeded::deserialize(packet_buf &buf)
{
    event_type type;

    buf.deserialize_4_bytes(&unused);
    type = ipv4_hdr.deserialize(buf);
    if (type != event_type::NO_ERROR) {
        return type;
    }

    buf.deserialize_bytes(datagram_data, sizeof(datagram_data));

    return event_type::NO_ERROR;
}

event_type icmp_timestamp::deserialize(packet_buf &buf)
{
    buf.deserialize_2_bytes(&identifier);
    buf.deserialize_2_bytes(&seq_no);
    buf.deserialize_4_bytes(&origin_timestamp);
    buf.deserialize_4_bytes(&receive_timestamp);
    buf.deserialize_4_bytes(&transmit_timestamp);

    return event_type::NO_ERROR;
}

event_type icmp_header::deserialize(packet_buf &buf)
{
    event_type evt_type;

    buf.deserialize_byte(&type);
    buf.deserialize_byte(&code);
    buf.deserialize_2_bytes(&checksum);

    if (type == ICMP_REQ) {
        buf.deserialize_2_bytes(&ping_req.id);
        buf.deserialize_2_bytes(&ping_req.seq_no);
    } else if (type == ICMP_REPLY) {
        buf.deserialize_2_bytes(&ping_reply.id);
        buf.deserialize_2_bytes(&ping_reply.seq_no);
    } else if (type == ICMP_REDIRECT) {
        evt_type = redir.deserialize(buf);
        if (evt_type != event_type::NO_ERROR) {
            return evt_type;
        }
    } else if (type == ICMP_TIME_EXCEED) {
        evt_type = time_exc.deserialize(buf);
        if (evt_type != event_type::NO_ERROR) {
            return evt_type;
        }
    } else if (type == ICMP_TIMESTAMP) {
        evt_type = timestamp.deserialize(buf);
        if (evt_type != event_type::NO_ERROR) {
            return evt_type;
        }
    } else if (type == ICMP_TIMESTAMP_REPLY) {
        evt_type = timestamp_reply.deserialize(buf);
        if (evt_type != event_type::NO_ERROR) {
            return evt_type;
        }
    }

    return event_type::NO_ERROR;
}

}
