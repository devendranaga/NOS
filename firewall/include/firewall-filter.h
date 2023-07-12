#ifndef __NOS_FIREWALL_FILTERS_H__
#define __NOS_FIREWALL_FILTERS_H__

#include <memory>
#include <packet.h>
#include <packet-buf.h>
#include <firewall-eth-filter.h>

namespace nos::firewall
{

class firewall_filter {
    public:
        explicit firewall_filter();
        ~firewall_filter();

        event_type run(packet_parser_state &state);

    private:
        std::shared_ptr<eth_filter> eth_f_;
};

}

#endif
