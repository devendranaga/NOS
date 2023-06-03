#ifndef __NOS_FIREWALL_EVENT_MGR_H__
#define __NOS_FIREWALL_EVENT_MGR_H__

#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <firewall_events.h>

namespace nos::firewall {

class firewall_event_mgr {
    public:
        ~firewall_event_mgr();
        firewall_event_mgr(const firewall_event_mgr &) = delete;
        firewall_event_mgr(const firewall_event_mgr &&) = delete;
        const firewall_event_mgr &operator=(const firewall_event_mgr &) = delete;
        const firewall_event_mgr &&operator=(const firewall_event_mgr &&) = delete;

        static firewall_event_mgr *instance() {
            static firewall_event_mgr evt_mgr;
            return &evt_mgr;
        }

        int init();
        void queue_event(firewall_event &event, packet_buf &pkt);

    private:
        explicit firewall_event_mgr() { }
        void event_upload_callback();

        std::unique_ptr<std::thread> evt_upload_thr_;
        std::queue<firewall_event> event_list_;
        std::mutex event_list_lock_;
        std::condition_variable event_list_cond_;
};

}

#endif
