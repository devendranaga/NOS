#ifndef __NOS_FIREWALL_INTF_H__
#define __NOS_FIREWALL_INTF_H__

#include <memory>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <nos_raw_socket.h>
#include <packet.h>

namespace nos::firewall {

class firewall_intf {
    public:
        explicit firewall_intf(std::shared_ptr<nos::core::logging> &log) :
                                log_(log)
        { }
        ~firewall_intf() = default;

        int create_raw(const std::string &ifname);

    private:
        void receive_callback();
        void parser_callback();
        void filter_callback();
        event_type parse_packet(packet_parser_state &parser_state);
        event_type parse_protocol(uint8_t protocol, packet_parser_state &parser_state);

        std::queue<packet_parser_state> parser_state_queue_;
        std::unique_ptr<nos::core::raw_socket> raw_;
        std::unique_ptr<std::thread> parser_thr_;
        std::unique_ptr<std::thread> filter_thr_;
        std::shared_ptr<nos::core::logging> log_;
        std::unique_ptr<std::thread> rx_thr_;
        std::queue<packet_buf> pkt_queue_;
        std::mutex pkt_queue_lock_;
        std::string ifname_;
};

}

#endif
