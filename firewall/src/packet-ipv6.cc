#include <packet-ipv6.h>

namespace nos::firewall
{

event_type ipv6_header::deserialize(packet_buf &buf)
{
    version = (buf.data[buf.off] & 0xF0) >> 4;
    if (version != IPV6_VERSION) {
        return event_type::IPV6_VERSION_INVAL;
    }
    traffic_class = ((buf.data[buf.off] & 0x0F) |
                     ((buf.data[buf.off + 1] & 0xF0) >> 4));
    buf.off ++;

    flow_label = (((buf.data[buf.off] & 0xF0) >> 4) |
                  ((buf.data[buf.off + 1]) |
                  ((buf.data[buf.off + 2]))));
    buf.off += 3;

    buf.deserialize_2_bytes(&payload_len);
    buf.deserialize_byte(&next_header);
    buf.deserialize_byte(&hop_limit);
    buf.deserialize_ip6addr(source_addr);
    buf.deserialize_ip6addr(dest_addr);

    return event_type::NO_ERROR;
}

}
