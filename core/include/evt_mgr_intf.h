#ifndef __NOS_EVT_MGR_INTF_H__
#define __NOS_EVT_MGR_INTF_H__

#include <stdint.h>
#include <string>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <unistd.h>
#include <sys/select.h>

namespace nos::core {

typedef std::function<void(void)> timer_cb;
typedef std::function<void(int)> socket_cb;

struct evt_socket_intf {
    socket_cb cb_;
    int id_;
    int fd_;
};

struct evt_timer_intf {
    timer_cb cb_;
    int id_;
    bool oneshot_;
    uint32_t sec_;
    uint64_t nsec_;
    int fd_;
};

class evt_mgr_intf {
    public:
        ~evt_mgr_intf();
        evt_mgr_intf(const evt_mgr_intf &) = delete;
        evt_mgr_intf(const evt_mgr_intf &&) = delete;
        const evt_mgr_intf &operator=(const evt_mgr_intf &) = delete;
        const evt_mgr_intf &&operator=(const evt_mgr_intf &&) = delete;

        static evt_mgr_intf *instance() {
            static evt_mgr_intf intf;
            return &intf;
        }

        int register_timer(uint32_t sec, uint64_t nsec, timer_cb cb, bool oneshot);
        void unregister_timer(int id);
        int register_socket(int fd, socket_cb cb);
        void unregister_socket(int id);
        void run();
        void terminate() { terminate_ = true; }
    private:
        explicit evt_mgr_intf() { }
        int get_max_fd();
        std::vector<evt_timer_intf> timer_list_;
        std::vector<evt_socket_intf> socket_list_;
        bool terminate_;
        fd_set allfd_;
        int timer_id_;
        int socket_id_;
};

}

#endif

