#ifndef __NOS_FIREWALL_ETH_FILTER_H__
#define __NOS_FIREWALL_ETH_FILTER_H__

#include <packet.h>
#include <packet-buf.h>
#include <firewall_events.h>
#include <firewall-rules.h>

namespace nos::firewall
{

class eth_filter {
    public:
        explicit eth_filter();
        ~eth_filter();

        event_type run(packet_parser_state &state,
                       const rule_config &rule);
};

}

#endif
