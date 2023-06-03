#include <getopt.h>
#include <nos_core.h>
#include <logger.h>

namespace nos::logger {

static void usage(const char *progname)
{
    fprintf(stderr, "<%s> <-p fileprefix> <-r rotate size in bytes>\n",
                    progname);
}

int log_service::read_cmdline(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "p:r:")) != -1) {
        switch (ret) {
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
    int ret;

    ret = read_cmdline(argc, argv);
    if (ret < 0) {
        throw std::runtime_error("failed to parse cmdline arguments");
    }

    evt_mgr_ = nos::core::evt_mgr_intf::instance();

    wr_thr_ = std::make_unique<std::thread>(&log_service::writer_thread, this);
    wr_thr_->detach();
}

log_service::~log_service()
{

}

void log_service::writer_thread()
{
    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void log_service::receive_logger_msg(int fd)
{
    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
