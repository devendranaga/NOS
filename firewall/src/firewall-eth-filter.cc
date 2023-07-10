#include <firewall-eth-filter.h>

namespace nos::firewall
{

eth_filter::eth_filter() { }
eth_filter::~eth_filter() { }

event_type eth_filter::run(packet_parser_state &state,
                           const rule_config &conf)
{
    return event_type::NO_ERROR;
}

}
