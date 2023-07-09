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
    } else {
        evt_type = redir.deserialize(buf);
        if (evt_type != event_type::NO_ERROR) {
            return evt_type;
        }
    }

    return event_type::NO_ERROR;
}

}
