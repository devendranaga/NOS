#include <nos_core.h>
#include <logger.h>

namespace nos::logger {

log_service::log_service()
{
    evt_mgr_ = nos::core::evt_mgr_intf::instance();

    rx_thr_ = std::make_unique<std::thread>(&log_service::receive_thread, this);
    rx_thr_->detach();

    wr_thr_ = std::make_unique<std::thread>(&log_service::writer_thread, this);
    wr_thr_->detach();
}

log_service::~log_service()
{

}

void log_service::writer_thread()
{

}

void log_service::receive_thread()
{

}

void log_service::run()
{
    evt_mgr_->run();
}

}

int main(int argc, char **argv)
{
    nos::logger::log_service ls;

    ls.run();
    return 0;
}
