#include <thread>
#include <mutex>
#include <firewall_event_mgr.h>

namespace nos::firewall {

void firewall_event_mgr::event_upload_callback()
{
    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int firewall_event_mgr::init()
{
    evt_upload_thr_ = std::make_unique<std::thread>(
                            &firewall_event_mgr::event_upload_callback,
                            this);
    evt_upload_thr_->detach();

    return 0;
}

firewall_event_mgr::~firewall_event_mgr()
{
}

}
