#include <packet.h>

namespace nos::firewall
{

event_type icmp6_multicast_address::deserialize(packet_buf &buf)
{
    buf.deserialize_byte(&rec_type);
    buf.deserialize_byte(&aux_data);
    buf.deserialize_2_bytes(&n_sources);
    buf.deserialize_ip6addr(mcast_addr);

    return event_type::NO_ERROR;
}

event_type icmp6_header::deserialize(packet_buf &buf)
{
    uint16_t reserved;

    buf.deserialize_byte(&type);
    buf.deserialize_byte(&code);
    buf.deserialize_2_bytes(&checksum);

    switch (type) {
        case ICMP6_ECHO_REQUEST: {
            buf.deserialize_2_bytes(&echo_req.identifier);
            buf.deserialize_2_bytes(&echo_req.sequence);
            echo_req.data_len = buf.data_len - buf.off;
        } break;
        case ICMP6_ECHO_REPLY: {
            buf.deserialize_2_bytes(&echo_rep.identifier);
            buf.deserialize_2_bytes(&echo_rep.sequence);
            echo_rep.data_len = buf.data_len - buf.off;
        } break;
        case ICMP6_MCAST_LISTENER_REPORT_V2: {
            buf.deserialize_2_bytes(&reserved);
            buf.deserialize_2_bytes(&mcast_listener.n_reports);
            for (uint32_t i = 0; i < mcast_listener.n_reports; i ++) {
                icmp6_multicast_address addr;

                addr.deserialize(buf);
                mcast_listener.addr_list.emplace_back(addr);
            }
        } break;
        default:
            return event_type::ICMP6_TYPE_UNSUPPORTED;
    }

    return event_type::NO_ERROR;
}

}
