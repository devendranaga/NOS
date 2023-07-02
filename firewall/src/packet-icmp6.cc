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
    event_type res;
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
        case ICMP6_ROUTER_ADVERTISEMENT: {
        } break;
        case ICMP6_NEIGHBOR_SOLICITATION: {
            buf.deserialize_4_bytes(&ns.reserved);
            buf.deserilaize_mac(ns.target_addr);
            while (buf.off < buf.data_len) {
                switch (buf.data[buf.off]) {
                    case ICMP6_OPT_SOURCE_LINK_LAYER: {
                        res = ns.source_link_layer.deserialize(buf);
                        if (res != event_type::NO_ERROR) {
                            return res;
                        }
                    } break;
                    default:
                        return event_type::ICMP6_TYPE_UNSUPPORTED_OPTION;
                }
            }
        } break;
        default:
            return event_type::ICMP6_TYPE_UNSUPPORTED;
    }

    return event_type::NO_ERROR;
}

event_type icmp6_option_source_link_layer::deserialize(packet_buf &buf)
{
    buf.deserialize_byte(&type);
    buf.deserialize_byte(&len);
    buf.deserilaize_mac(link_layer_addr);

    return event_type::NO_ERROR;
}

}
