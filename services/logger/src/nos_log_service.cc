#include <nos_log_service.h>

namespace nos::logger {

void nos_log_serv_context::rx_log_pkt()
{
    char sender_ip[30];
    uint32_t sender_port;
    int ret;

    while (1) {
        nos_log_rx_msg rx_msg;

        /* Receive one packet from the local socket. */
        ret = nos_udp_socket_read(serv_sock_,
                                  rx_msg.msg,
                                  sizeof(rx_msg.msg),
                                  sender_ip,
                                  &sender_port);
        if (ret < 0) {
            continue;
        }

        rx_msg.msg_len = ret;

        /* Queue the messge. */
        {
            std::unique_lock<std::mutex> lock(rx_msg_q_lock_);
            rx_msg_q_.push(rx_msg);
        }
    }
}

static void nos_log_serv_create_filename(char *filename,
                                         uint32_t filename_len,
                                         const char *file_prefix)
{
    time_t now;
    struct tm *t;
    struct timespec tp;

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &tp);

    snprintf(filename, filename_len,
                    "%s_%04d_%02d_%02d_%02d_%02d_%02d_%04ld.txt",
                    file_prefix, t->tm_year + 1900, t->tm_mon + 1,
                    t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
                    tp.tv_nsec / 1000000U);
}

static int nos_log_serv_open_file(char *filename,
                                  uint32_t filename_len,
                                  const char *file_prefix)
{
    nos_log_serv_create_filename(filename, filename_len, file_prefix);
    return nos_fileio_open(filename, "wb");
}

static void nos_log_serv_write_msg(int file_fd, nos_log_rx_msg *rx_msg)
{
    nos_logger_msg_t *log_msg;
    nos_logger_log_data_t *log_data;
    int len = 0;

    log_msg = (nos_logger_msg_t *)(rx_msg->msg);
    log_data = (nos_logger_log_data_t *)(log_msg->val);

    len = log_msg->len - sizeof(nos_logger_log_data_t);

    if (len <= 0) {
        return;
    }

    if (log_msg->type == NOS_LOGGER_MSG_TYPE_LOG_DATA) {
        nos_fileio_write(file_fd, log_data->data, len);
    }
}

void nos_log_serv_context::write_log_pkt()
{
    nos_log_serv_command_args *cmd_args;

    cmd_args = nos_log_serv_command_args::instance();

    file_fd_ = nos_log_serv_open_file(cmd_args->filename,
                                      strlen(cmd_args->filename),
                                      cmd_args->log_file_prefix);
    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        {
            std::unique_lock<std::mutex> lock(rx_msg_q_lock_);
            int q_len = rx_msg_q_.size();
            do {
                nos_log_rx_msg msg = rx_msg_q_.front();
                nos_log_serv_write_msg(file_fd_, &msg);
                q_len = rx_msg_q_.size();
            } while (q_len > 0);
        }
    }
}

static void usage(const char *progname)
{
    fprintf(stderr, "<%s>  [-f filename] "
                    "\t [-L log file prefix] "
                    "\t [-s file size in bytes]\n",
                    progname);
}

int nos_log_serv_command_args::parse(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "f:L:s:")) != -1) {
        switch (ret) {
            case 'f':
                filename = strdup(optarg);
            break;
            case 'L':
                log_file_prefix = strdup(optarg);
            break;
            case 's':
                ret = nos_util_convert_u32(optarg, &log_file_size_bytes);
                if (ret < 0) {
                    return -1;
                }
            break;
            default:
                usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

int nos_log_serv_context::init(int argc, char **argv)
{
    int ret;

    ret = nos_log_serv_command_args::instance()->parse(argc, argv);
    if (ret < 0) {
        nos_log(NOS_LOG_SINK_CONSOLE, NOS_LOG_LEVEL_ERROR,
                "failed to parse command line args\n");
        return -1;
    }

    serv_sock_ = nos_udp_server_init(NOS_LOG_SERVICE_IP,
                                     NOS_LOG_SERVICE_PORT);
    if (serv_sock_ < 0) {
        nos_log(NOS_LOG_SINK_CONSOLE, NOS_LOG_LEVEL_ERROR,
                "failed to create server socket [%s:%d]\n",
                NOS_LOG_SERVICE_IP, NOS_LOG_SERVICE_PORT);
        return -1;
    }

    nos_log(NOS_LOG_SINK_CONSOLE, NOS_LOG_LEVEL_INFO,
            "server socket [%s:%d] created ok [%d]\n",
            NOS_LOG_SERVICE_IP, NOS_LOG_SERVICE_PORT, serv_sock_);

    /* Create Log receive thread. */
    log_rx_thr_ = std::make_unique<std::thread>(
                                &nos_log_serv_context::rx_log_pkt, this);
    log_rx_thr_->detach();

    /* Create Log writer thread. */
    log_wr_thr_ = std::make_unique<std::thread>(
                                &nos_log_serv_context::write_log_pkt, this);
    log_wr_thr_->detach();

    return 0;
}

void nos_log_serv_context::start()
{
    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

nos_log_serv_context::~nos_log_serv_context()
{
    if (serv_sock_ > 0) {
        nos_udp_close(serv_sock_);
    }
}

}

int main(int argc, char **argv)
{
    nos::logger::nos_log_serv_context ctx;
    int ret;

    ret = ctx.init(argc, argv);
    if (ret == 0) {
        ctx.start();
    }

    return 0;
}

