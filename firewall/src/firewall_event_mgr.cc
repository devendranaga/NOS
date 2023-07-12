#include <thread>
#include <mutex>
#include <firewall_event_mgr.h>

namespace nos::firewall {

void firewall_event_mgr::queue_event(firewall_event &event, packet_buf &pkt)
{
    {
        std::unique_lock<std::mutex> lock(event_list_lock_);
        event_list_.push(event);
    }
}

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

void firewall_event_mgr::make(packet_parser_state &state,
                              event_result res,
                              event_type descr,
                              uint32_t rule_id)
{
    firewall_event evt;

    evt.make(state, res, descr, rule_id);
    queue_event(evt, state.pkt_buf);
}

firewall_event_mgr::~firewall_event_mgr()
{
}

}
