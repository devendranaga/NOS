#ifndef __NOS_FIREWALL_H__
#define __NOS_FIREWALL_H__

#include <vector>
#include <memory>
#include <firewall_config.h>
#include <firewall_intf.h>

namespace nos::firewall {

class firewall_ctx {
    public:
        explicit firewall_ctx();
        ~firewall_ctx();

        int init();

        void run();

    private:
        std::vector<std::shared_ptr<firewall_intf>> intf_list_;
};

}

#endif
