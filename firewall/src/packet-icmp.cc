#include <packet-icmp.h>

namespace nos::firewall
{

event_type icmp_header::deserialize(packet_buf &buf)
{
    buf.deserialize_byte(&type);
    buf.deserialize_byte(&code);
    buf.deserialize_2_bytes(&checksum);

    if (type == PING_REQ) {
        buf.deserialize_2_bytes(&ping_req.id);
        buf.deserialize_2_bytes(&ping_req.seq_no);
    } else if (type == PING_REPLY) {
        buf.deserialize_2_bytes(&ping_reply.id);
        buf.deserialize_2_bytes(&ping_reply.seq_no);
    }

    return event_type::NO_ERROR;
}

}
