#ifndef __NOS_LOGGER_H__
#define __NOS_LOGGER_H__

#include <string>
#include <memory>
#include <thread>
#include <queue>
#include <mutex>
#include <nos_core.h>

namespace nos::logger {

struct logger_config {
    std::string file_prefix;
    uint32_t rotate_size_bytes;
};

struct log_msg {
    uint8_t data[8192];
    uint32_t len;
};

class log_service {
    public:
        explicit log_service();
        ~log_service();

        void run();

    private:
        int read_cmdline(int argc, char **argv);
        void receive_thread();
        void writer_thread();
        std::unique_ptr<std::thread> rx_thr_;
        std::unique_ptr<std::thread> wr_thr_;
        nos::core::evt_mgr_intf *evt_mgr_;
        std::queue<log_msg> msg_q_;
        nos::core::file_intf file_;
        std::mutex msg_q_lock_;
        std::string file_name_;
        logger_config conf_;
};

}

#endif
