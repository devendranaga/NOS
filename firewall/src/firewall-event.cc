#include <string.h>
#include <event_types.h>
#include <packet.h>
#include <firewall_events.h>

namespace nos::firewall {

int firewall_event::make(packet_parser_state &state,
                         event_result res,
                         event_type descr,
                         uint32_t rule_id)
{
    strcpy(intf, state.pkt_buf.intf);
    this->res = res;
    this->descr = descr;
    this->rule_id = rule_id;

    memcpy(sender_mac,
           state.pkt.eth_h.srcmac, sizeof(state.pkt.eth_h.srcmac));
    memcpy(target_mac,
           state.pkt.eth_h.dstmac, sizeof(state.pkt.eth_h.dstmac));
    ethertype = state.pkt.eth_h.ethertype;

    pkt = state.pkt_buf;

    return 0;
}

}
