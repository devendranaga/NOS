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
    strcpy(intf, state.pkt_buf.intf.c_str());
    this->res = res;
    this->descr = descr;
    this->rule_id = rule_id;

    memcpy(sender_mac,
           state.pkt.eth_h.srcmac, sizeof(state.pkt.eth_h.srcmac));
    memcpy(target_mac,
           state.pkt.eth_h.dstmac, sizeof(state.pkt.eth_h.dstmac));
    ethertype = state.pkt.eth_h.ethertype;

    if (state.pkt.has_ipv4()) {
        src_ipaddr = state.pkt.ipv4_h.source_ipaddr;
        dest_ipaddr = state.pkt.ipv4_h.dest_ipaddr;
        protocol = state.pkt.ipv4_h.protocol;
        switch (protocol) {
            case PROTOCOL_TCP:
                src_port = state.pkt.tcp_h.source_port;
                dst_port = state.pkt.tcp_h.dest_port;
            break;
            case PROTOCOL_UDP:
                src_port = state.pkt.udp_h.source_port;
                dst_port = state.pkt.udp_h.dest_port;
            break;
            default:
                return -1;
        }
    }

    pkt = state.pkt_buf;

    return 0;
}

}
