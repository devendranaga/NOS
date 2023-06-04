#ifndef __NOS_FIREWALL_INTF_H__
#define __NOS_FIREWALL_INTF_H__

#include <memory>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <raw_socket.h>
#include <packet.h>

namespace nos::firewall {

class firewall_intf {
    public:
        explicit firewall_intf() = default;
        ~firewall_intf() = default;

        int create_raw(const std::string &ifname);

    private:
        void receive_callback();
        void parser_callback();
        void filter_callback();
        event_type parse_packet(packet_parser_state &parser_state);

        std::queue<packet_parser_state> parser_state_queue_;
        std::unique_ptr<nos::core::raw_socket> raw_;
        std::unique_ptr<std::thread> parser_thr_;
        std::unique_ptr<std::thread> filter_thr_;
        std::unique_ptr<std::thread> rx_thr_;
        std::queue<packet_buf> pkt_queue_;
        std::mutex pkt_queue_lock_;
};

}

#endif
