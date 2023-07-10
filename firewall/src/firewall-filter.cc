#include <firewall-rules.h>
#include <firewall-filter.h>

namespace nos::firewall
{

firewall_filter::firewall_filter()
{
    eth_f_ = std::make_shared<eth_filter>();
}

firewall_filter::~firewall_filter() { }

event_type firewall_filter::run(packet_parser_state &state)
{
    std::vector<rule_config> rules;
    event_type res = event_type::UNKNOWN_ERROR;

    rules = firewall_rules::instance()->get();

    for (auto it : rules) {
        if (it.mac_rule_available) {
            res = eth_f_->run(state, it);
            if (res != event_type::NO_ERROR) {
                break;
            }
        }
    }

    return res;
}

}
