/**
 * @brief - Implements Event Mgr.
 * 
 * @copyright - 2023-present All rights reserved. Ask me for license.
 * @author - Devendra Naga.
 */
#include <cstdint>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <nos_evt_mgr.h>

namespace nos::core::lib {

int timer_context::create_timer(uint32_t sec, uint64_t nsec, const timer_fn &fn, bool oneshot_timer)
{
    timer_info info(sec, nsec, fn, oneshot_timer);
    int ret;

    timer_id_cur_ ++;

    info.timer_id = timer_id_cur_;
    info.timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (info.timer_fd < 0) {
        return -1;
    }

    struct itimerspec it;

    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec = sec;
    it.it_value.tv_nsec = nsec;

    if (oneshot_timer) {
        it.it_interval.tv_sec = sec;
        it.it_interval.tv_nsec = nsec;
    }

    ret = timerfd_settime(info.timer_fd, 0, &it, NULL);
    if (ret < 0) {
        close(info.timer_fd);
        return -1;
    }

    timer_list_.emplace_back(info);

    return 0;
}

int timer_context::delete_timer(int timer_id)
{
    std::vector<timer_info>::iterator it;

    for (it = timer_list_.begin(); it != timer_list_.end(); it ++) {
        if (it->timer_id == timer_id) {
            break;
        }
    }

    if (it != timer_list_.end()) {
        if (it->timer_fd > 0) {
            close(it->timer_id);
        }
        timer_list_.erase(it);
    }

    return 0;
}

int timer_context::handle_timer(fd_set &fds)
{
    uint64_t elapsed = 0;
    int ret = -1;

    for (auto it : timer_list_) {
        if (FD_ISSET(it.timer_fd, &fds)) {

            ret = read(it.timer_fd, &elapsed, sizeof(elapsed));
            if (ret < 0) {
                break;
            }

            it.fn();
            ret = 0;
            break;
        }
    }

    return ret;
}

int socket_context::create_socket(int fd, const socket_fn &fn)
{
    socket_info info(fd, fn);

    socket_id_cur_ ++;
    info.socket_id = socket_id_cur_;

    socket_list_.emplace_back(info);

    return 0;
}

int socket_context::delete_socket(int socket_id)
{
    std::vector<socket_info>::iterator it;
    int ret = -1;

    for (it = socket_list_.begin(); it != socket_list_.end(); it ++) {
        if (it->socket_id == socket_id) {
            break;
        }
    }

    if (it != socket_list_.end()) {
        socket_list_.erase(it);
        ret = 0;
    }

    return ret;
}

int socket_context::handle_socket(fd_set &fds)
{
    std::vector<socket_info>::iterator it;
    int ret = -1;

    for (it = socket_list_.begin(); it != socket_list_.end(); it ++) {
        if (FD_ISSET(it->fd, &fds)) {
            it->fn(it->fd);
            ret = 0;
            break;
        }
    }

    return ret;
}

int evt_mgr::register_timer(uint32_t sec, uint64_t nsec, const timer_fn &fn, bool oneshot)
{
    return timer_ctx_.create_timer(sec, nsec, fn, oneshot);
}

int evt_mgr::register_socket(int fd, const socket_fn &fn)
{
    return socket_ctx_.create_socket(fd, fn);
}

int evt_mgr::unregister_timer(int timer_id)
{
    return timer_ctx_.delete_timer(timer_id);
}

int evt_mgr::unregister_socket(int socket_id)
{
    return socket_ctx_.delete_socket(socket_id);
}

int evt_mgr::max_fd()
{
    int max = 0;

    for (auto it : timer_ctx_.timer_list_) {
        if (max < it.timer_fd) {
            max = it.timer_fd;
        }
    }

    for (auto it : socket_ctx_.socket_list_) {
        if (max < it.fd) {
            max = it.fd;
        }
    }

    return max;
}

void evt_mgr::run()
{
    fd_set cur_fds;
    int ret;

    while (1) {
        FD_ZERO(&cur_fds);

        cur_fds = reg_fd_;

        if (terminate_) {
            break;
        }

        ret = select(max_fd() + 1, &cur_fds, NULL, NULL, NULL);
        if (ret < 0) {
            break;
        } else {
            ret = timer_ctx_.handle_timer(cur_fds);
            if (ret < 0) {
                ret = socket_ctx_.handle_socket(cur_fds);
            }
        }
    }
}

evt_mgr::evt_mgr()
{
    terminate_ = false;
    FD_ZERO(&reg_fd_);
}

}
