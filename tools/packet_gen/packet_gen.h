#ifndef __NOS_PACKET_GEN_H__
#define __NOS_PACKET_GEN_H__

#include <cstdint>
#include <string>
#include <nos_core.h>

namespace nos::packet_gen
{

class packet_gen {
    public:
        explicit packet_gen(int argc, char **argv);
        ~packet_gen();
        void run();
    private:
        std::string interface_name_;
        bool pcap_replay_;
        std::string pcap_replay_file_;
        uint32_t replay_intvl_ms_;
        std::shared_ptr<nos::core::raw_socket> raw_;
        nos::core::evt_mgr_intf *evt_mgr_;

        void pcap_replay_callback_fn();
};

}

#endif

