#ifndef __NOS_LOGGER_H__
#define __NOS_LOGGER_H__

#include <cstring>
#include <string>
#include <memory>
#include <thread>
#include <queue>
#include <mutex>
#include <nos_core.h>

namespace nos::logger {

enum log_service_type {
    Log_To_File     = 0x0001,
    Log_To_Syslog   = 0x0002,
    Log_To_Dlt      = 0x0004,
};

struct logger_config {
    std::string server_ipaddr;
    int server_port;
    std::string file_prefix;
    uint32_t rotate_size_bytes;
    log_service_type service_type;
};

struct log_msg {
    uint8_t data[8192];
    uint32_t len;

    explicit log_msg() {
        std::memset(data, 0, sizeof(data));
        len = 0;
    }
};

/**
 * @brief - Log kernel message.
 */
class log_kernel {
    public:
        explicit log_kernel();
        ~log_kernel() { fi_.close(); }

        void init_kernel_log(nos::core::file_intf &fi);
        int write(const log_msg &msg);

    private:
        const std::string dev_kmsg_ = "/dev/kmsg";
        nos::core::file_intf kernel_fi_;
        nos::core::file_intf fi_;
};

/**
 * Implements file i/o logging interface.
*/
class log_fileio {
    public:
        explicit log_fileio(logger_config &conf) {
            conf_ = conf;
            file_off_ = 0;
        }
        ~log_fileio() = default;

        void new_filename();
        void init_kernel_log();
        void write(const log_msg &msg);
        void write_kernel_log(const log_msg &msg);

    private:
        std::shared_ptr<log_kernel> kern_log_;
        logger_config conf_;
        std::string file_name_;
        nos::core::file_intf fi_;
        uint32_t file_off_;
};

/**
 * Implements base log service class that holds the logger context.
*/
class log_service {
    public:
        explicit log_service(int argc, char **argv);
        ~log_service();

        void run();

    private:
        /**
         * @brief - Parse command line configuration data.
        */
        int read_cmdline(int argc, char **argv);

        /**
         * @brief - Receive a logging message over udp.
        */
        void receive_logger_msg(int fd);

        /**
         * @brief - Writer thread handles the logging of received log data.
        */
        void writer_thread();
        std::unique_ptr<nos::core::udp_server> udp_server_;
        std::unique_ptr<std::thread> wr_thr_;
        nos::core::evt_mgr_intf *evt_mgr_;
        std::queue<log_msg> msg_q_;
        std::shared_ptr<log_fileio> file_io_;
        std::mutex msg_q_lock_;
        logger_config conf_;
};

}

#endif
