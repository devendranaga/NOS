#ifndef __NOS_FIREWALL_H__
#define __NOS_FIREWALL_H__

#include <vector>
#include <memory>
#include <jsoncpp/json/json.h>
#include <firewall_config.h>
#include <firewall_intf.h>
#include <firewall_event_mgr.h>
#include <nos_core.h>

namespace nos::firewall {

class firewall_ctx {
    public:
        explicit firewall_ctx();
        ~firewall_ctx();

        int init(const std::string &conf_file);

        void run();

    private:
        std::vector<std::shared_ptr<firewall_intf>> intf_list_;
        std::shared_ptr<nos::core::logging> log_;
        nos::core::evt_mgr_intf *evt_mgr_;
};

}

#endif
