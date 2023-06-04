#include <firewall.h>

namespace nos::firewall {

#define VALIDATE_AND_FAIL(__type) {\
    if (__type != event_type::NO_ERROR) {\
        return __type;\
    }\
}

event_type firewall_intf::parse_packet(packet_parser_state &state)
{
    event_type type;

    type = state.pkt.eth_h.deserialize(state.pkt_buf);
    VALIDATE_AND_FAIL(type);

    switch (state.pkt.eth_h.ethertype) {
        case ETHERTYPE_ARP:
        break;
        case ETHERTYPE_IPV4:
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

    {
        std::unique_lock<std::mutex> lock(pkt_queue_lock_);
        q_len = pkt_queue_.size();
        while (q_len > 0) {
            packet_parser_state state;

            state.pkt_buf = pkt_queue_.front();
            pkt_queue_.pop();

            type = parse_packet(state);
            if (type != event_type::NO_ERROR) {
                firewall_event evt;
                evt.make(state, event_result::Deny, type, 0);
            } else {

            }
            q_len = pkt_queue_.size();
        }
    }
}

}
