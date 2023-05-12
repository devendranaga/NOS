#ifndef __NOS_LOG_SERVICE_H__
#define __NOS_LOG_SERVICE_H__

#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <thread>
#include <memory>
#include <mutex>
#include <queue>
#include <nos_logger_msg_intf.h>
#include <nos_core.h>

#define NOS_LOG_SERVICE_CONFIG "./nos_log_service.conf"

namespace nos::logger {

struct nos_log_serv_command_args {
    char        *log_file_prefix;
    uint32_t    log_file_size_bytes;

    static nos_log_serv_command_args *instance() {
        static nos_log_serv_command_args args;
        return &args;
    }
    int parse(int argc, char **argv);

    private:
        explicit nos_log_serv_command_args() { }
};

struct nos_log_rx_msg {
    uint8_t msg[4096];
    uint16_t msg_len;

    explicit nos_log_rx_msg() {
        memset(msg, 0, sizeof(msg));
        msg_len = 0;
    }
    ~nos_log_rx_msg() { }
};

class nos_log_serv_context {
    public:
        explicit nos_log_serv_context() = default;
        ~nos_log_serv_context();

        int init(int argc, char **argv);
        void start();

    private:
        std::unique_ptr<std::thread> log_rx_thr_;
        std::unique_ptr<std::thread> log_wr_thr_;
        std::queue<nos_log_rx_msg> rx_msg_q_;
        std::mutex rx_msg_q_lock_;
        int serv_sock_;
        int file_fd_;
        char log_file_name_[512];

        void rx_log_pkt();
        void write_log_pkt();
};

}

#endif
