#ifndef __NOS_FIREWALL_INTF_H__
#define __NOS_FIREWALL_INTF_H__

#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <raw_socket.h>

namespace nos::firewall {

class firewall_intf {
    public:
        explicit firewall_intf() = default;
        ~firewall_intf() = default;

        int create_raw(const std::string &ifname);

    private:
        void receive_callback();

        std::unique_ptr<nos::core::raw_socket> raw_;
        std::unique_ptr<std::thread> rx_thr_;
};

}

#endif
