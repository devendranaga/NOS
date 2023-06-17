/**
 * @brief - Implements logger service.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <memory>
#include <getopt.h>
#include <nos_core.h>
#include <logger.h>

namespace nos::logger {

/**
 * @brief - Display the usage.
*/
static void usage(const char *progname)
{
    fprintf(stderr, "<%s> <-p fileprefix> <-r rotate size in bytes>\n"
                    "\t <-t type <0x01 - file, 0x02 - syslog, 0x04 - Dlt>\n"
                    "\t <-i ip address> <-P port>\n",
                    progname);
}

int log_service::read_cmdline(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "t:i:P:p:r:")) != -1) {
        switch (ret) {
            case 't':
                conf_.service_type = (log_service_type)std::atoi(optarg);
            break;
            case 'i':
                conf_.server_ipaddr = optarg;
            break;
            case 'P':
                conf_.server_port = std::atoi(optarg);
            break;
            case 'p':
                conf_.file_prefix = std::string(optarg);
            break;
            case 'r':
                conf_.rotate_size_bytes = std::atoi(optarg);
            break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    return 0;
}

log_service::log_service(int argc, char **argv)
{
    std::shared_ptr<nos::core::logging> log;
    int ret;

    ret = read_cmdline(argc, argv);
    if (ret < 0) {
        throw std::runtime_error("failed to parse cmdline arguments");
    }

    log = nos::core::log_factory::instance()->create(
                    nos::core::logger_type::Console);
    evt_mgr_ = nos::core::evt_mgr_intf::instance();

    log->info("Created Event Manager\n");

    udp_server_ = std::make_unique<nos::core::udp_server>(conf_.server_ipaddr,
                                                          conf_.server_port);
    if (!udp_server_) {
        throw std::runtime_error("failed to create udp server");
    }

    log->info("Created udp server %s:%d\n", conf_.server_ipaddr.c_str(),
                                            conf_.server_port);

    auto rx_cb = std::bind(&log_service::receive_logger_msg, this, std::placeholders::_1);
    evt_mgr_->register_socket(udp_server_->get_socket(), rx_cb);

    log->info("Rx callback registered\n");

    wr_thr_ = std::make_unique<std::thread>(&log_service::writer_thread, this);
    wr_thr_->detach();

    log->info("Create Writer thread\n");
}

log_service::~log_service()
{

}

void log_fileio::new_filename()
{
    char filename_str[256];
    nos::core::time_intf t;
    nos::core::timestamp_cal t_cal;
    nos::core::timestamp_ns t_ns;

    t.get_calendar(t_cal);
    t.get_ns_realtime(t_ns);

    if (fi_.is_file_opened()) {
        fi_.close();
    }
    /* Create a new file and write it. */
    snprintf(filename_str, sizeof(filename_str),
                            "%s_%04d_%02d_%02d_%02d_%02d_%02d_%04lu.bin",
                            conf_.file_prefix.c_str(),
                            t_cal.year, t_cal.mon, t_cal.day, t_cal.hour,
                            t_cal.min, t_cal.sec, t_ns.nsec / 1000000UL);
    file_name_ = filename_str;

    fi_.create(file_name_, nos::core::file_mode::MODE_SECURITY);
}

void log_fileio::write(const log_msg &msg)
{
    if (conf_.service_type & log_service_type::Log_To_File) {
        nos_log_intf *intf = (nos_log_intf *)msg.data;

        if (intf->type == LOG_MSG_TYPE_LOGDATA) {
            nos_log_data *log_data = (nos_log_data *)intf->data;
            if (log_data->len < 0) {
                return;
            }

            if (file_off_ > conf_.rotate_size_bytes) {
                file_off_ = 0;
                new_filename();
            }
            file_off_ += fi_.write(log_data->data, log_data->len);
        }
    }
}

void log_fileio::init_kernel_log()
{
    /**
     * Initialize the kernel log.
    */
    kern_log_ = std::make_shared<log_kernel>();
    kern_log_->init_kernel_log(fi_);
}

/**
 * Initialize the kernel ring buffer fd
*/
log_kernel::log_kernel()
{
    int ret;

    ret = kernel_fi_.open(dev_kmsg_, nos::core::file_ops::READ_WRITE);
    if (ret < 0) {
        throw std::runtime_error("failed to open " + dev_kmsg_);
    }
}

void log_kernel::init_kernel_log(nos::core::file_intf &fi)
{
    char msg[4096] = {0};
    char *ptr;
    uint32_t off = 0;
    int ret = 0;

    fi_ = fi;

    /**
     * Write all  messages to the log.
    */
    while (1) {
        std::memset(msg, 0, sizeof(msg));
        ret = kernel_fi_.read((uint8_t *)msg, sizeof(msg));
        if (ret <= 0) {
            break;
        }
        ptr = strstr(msg, "-;");
        if (ptr) {
            off = ptr - msg + 2;
            fi_.write((const uint8_t *)(msg + off), ret - off);
        }
    }
}

void log_service::writer_thread()
{
    file_io_ = std::make_shared<log_fileio>(conf_);
    file_io_->new_filename();

    /**
     * initialize kernel log buffer.
    */
    file_io_->init_kernel_log();

    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        {
            std::unique_lock<std::mutex> lock(msg_q_lock_);
            int q_len = msg_q_.size();
            while (q_len > 0) {
                log_msg msg;

                msg = msg_q_.front();
                file_io_->write(msg);
                msg_q_.pop();
                q_len = msg_q_.size();
            }
        }
    }
}

void log_service::receive_logger_msg(int fd)
{
    std::shared_ptr<nos::core::logging> log;
    std::string sender_addr;
    int sender_port;
    log_msg msg;
    int ret;

    log = nos::core::log_factory::instance()->create(
                    nos::core::logger_type::Console);
    while (1) {
        ret = udp_server_->recv(msg.data, sizeof(msg.data), sender_addr, &sender_port);
        if (ret < 0) {
            log->err("Receive on socket failed %d\n", ret);
            break;
        }
        msg.len = ret;
        {
            std::unique_lock<std::mutex> lock(msg_q_lock_);
            msg_q_.push(msg);
        }
    }
}

void log_service::run()
{
    evt_mgr_->run();
}

}

int main(int argc, char **argv)
{
    nos::logger::log_service ls(argc, argv);

    ls.run();
    return 0;
}
