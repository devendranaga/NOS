/**
 * @brief - Implements Firewall parser.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <firewall.h>

namespace nos::firewall {

#define VALIDATE_AND_FAIL(__type) {\
    if (__type != event_type::NO_ERROR) {\
        return __type;\
    }\
}

event_type firewall_intf::parse_protocol(uint8_t protocol, packet_parser_state &state)
{
    event_type type = event_type::UNSUPPORTED_PROTOCOL;

    switch (protocol) {
        case PROTOCOL_UDP: {
            type = state.pkt.udp_h.deserialize(state.pkt_buf);
        } break;
        case PROTOCOL_ICMP: {
            type = state.pkt.icmp_h.deserialize(state.pkt_buf);
        } break;
        case PROTOCOL_ICMP6: {
            type = state.pkt.icmp6_h.deserialize(state.pkt_buf);
        } break;
        case PROTOCOL_TCP: {
            type = state.pkt.tcp_h.deserialize(state.pkt_buf, log_);
        } break;
        default:
            return event_type::UNSUPPORTED_PROTOCOL;
    }

    return type;
}

event_type firewall_intf::parse_packet(packet_parser_state &state)
{
    event_type type;

    /* Find the ethertype to parse the next header. */
    type = state.pkt.eth_h.deserialize(state.pkt_buf, log_);
    VALIDATE_AND_FAIL(type);

l2_parse:
    /* Parse the next header after the ethertype. */
    switch (state.pkt.eth_h.ethertype) {
        case ETHERTYPE_ARP:
            type = state.pkt.arp_h.deserialize(state.pkt_buf);
        break;
        case ETHERTYPE_IPV4:
            type = state.pkt.ipv4_h.deserialize(state.pkt_buf);
            if (type == event_type::NO_ERROR) {
                type = parse_protocol(state.pkt.ipv4_h.protocol, state);
            }
        break;
        case ETHERTYPE_IPV6:
            type = state.pkt.ipv6_h.deserialize(state.pkt_buf);
            if (type == event_type::NO_ERROR) {
                type = parse_protocol(state.pkt.ipv6_h.next_header, state);
            }
        break;
        case ETHERTYPE_MACSEC:
            type = state.pkt.macsec_h.deserialize(state.pkt_buf);
            if (type == event_type::NO_ERROR) {
                /**
                 * If the packet is authenticated only, then lets parse it.
                */
                if (!state.pkt.macsec_h.is_secured()) {
                    goto l2_parse;
                }
            }
        break;
        default:
            return event_type::UNSUPPORTED_ETHERTYPE;
    }

    return type;
}

void firewall_intf::parser_callback()
{
    event_type type;
    int q_len;

    while (1) {
        {
            std::unique_lock<std::mutex> lock(pkt_queue_lock_);
            pkt_queue_cond_.wait(lock);

            q_len = pkt_queue_.size();
            while (q_len > 0) {
                packet_parser_state state;

                state.pkt_buf = pkt_queue_.front();
                pkt_queue_.pop();

                type = parse_packet(state);

                /*
                 * Parsing has failed.
                 */
                if (type != event_type::NO_ERROR) {
                    /* Make and queue the event. */
                    firewall_event_mgr::instance()->make(state,
                                                   event_result::Deny,
                                                   type,
                                                   0);
                } else {

                }
                q_len = pkt_queue_.size();
            }
        }
    }
}

}
