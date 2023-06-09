/**
 * @brief - implements the event manager.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <time.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <nos_evt_mgr_intf.h>

namespace nos::core {

int evt_mgr_intf::register_timer(uint32_t sec, uint64_t nsec, timer_cb cb, bool oneshot)
{
    evt_timer_intf timer;
    int ret;

    timer.fd_ = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timer.fd_ < 0) {
        return -1;
    }

    struct itimerspec ispec;

    timer.oneshot_ = oneshot;
    timer.cb_ = cb;
    timer.sec_ = sec;
    timer.nsec_ = nsec;

    ispec.it_value.tv_sec = sec;
    ispec.it_value.tv_nsec = nsec;
    /**
     * if its not oneshot, then register repeat.
    */
    if (oneshot == false) {
        ispec.it_interval.tv_sec = sec;
        ispec.it_interval.tv_nsec = nsec;
    }

    timer_id_ ++;

    timer.id_ = timer_id_;

    ret = timerfd_settime(timer.fd_, 0, &ispec, nullptr);
    if (ret < 0) {
        close(timer.fd_);
        return -1;
    }

    FD_SET(timer.fd_, &allfd_);

    /**
     * Queue and organize the timers.
    */
    timer_list_.emplace_back(timer);

    return timer_id_;
}

void evt_mgr_intf::unregister_timer(int id)
{
    std::vector<evt_timer_intf>::iterator it;

    for (it = timer_list_.begin(); it != timer_list_.end(); it ++) {
        if (it->id_ == id) {
            break;
        }
    }

    if (it != timer_list_.end()) {
        close(it->fd_);
        timer_list_.erase(it);
        FD_CLR(it->fd_, &allfd_);
    }
}

int evt_mgr_intf::register_socket(int fd, socket_cb cb)
{
    evt_socket_intf sock;

    sock.cb_ = cb;
    sock.fd_ = fd;

    socket_id_ ++;

    sock.id_ = socket_id_;

    FD_SET(fd, &allfd_);

    socket_list_.emplace_back(sock);

    return socket_id_;    
}

void evt_mgr_intf::unregister_socket(int id)
{
    std::vector<evt_socket_intf>::iterator it;

    for (it = socket_list_.begin(); it != socket_list_.end(); it ++) {
        if (it->id_ == id) {
            break;
        }
    }

    if (it != socket_list_.end()) {
        socket_list_.erase(it);
        FD_CLR(it->fd_, &allfd_);
    }
}

void evt_thread::thread_func()
{
    while (1) {
        {
            /**
             * Wait for the event via the queue_work call and if some work
             * is available, deque and execute.
            */
            std::unique_lock<std::mutex> lock(lock_);
            cond_.wait(lock);
            int q_len = exec_cbs_.size();
            while (q_len > 0) {
                exec_cb cb;

                cb = exec_cbs_.front();
                cb();

                exec_cbs_.pop();
                q_len = exec_cbs_.size();
            }
        }
    }
}

evt_thread::evt_thread()
{
    thread_ = std::make_shared<std::thread>(&evt_thread::thread_func, this);
    thread_->detach();
}

evt_thread::~evt_thread()
{

}

int evt_mgr_intf::init(const evt_mgr_config &conf)
{
    conf_ = conf;

    thr_pool_.n_threads_ = conf_.n_threads;
    for (uint32_t i = 0; i < thr_pool_.n_threads_; i ++) {
        std::shared_ptr<evt_thread> t;

        t = std::make_shared<evt_thread>();

        thr_pool_.thread_list_.emplace_back(t);
    }

    return 0;
}

void evt_mgr_intf::queue_work(const exec_cb &cb)
{
    int min_work = 0;
    int thread_pool_index = 0;

    /**
     * Find a minimum queue size and queue the exec_cb to that thread queue and
     * signal the thread.
    */
    for (uint32_t id = 0; id < thr_pool_.n_threads_; id ++) {
        int n_cbs = 0;

        n_cbs = thr_pool_.thread_list_[id]->exec_cbs_.size();
        if (min_work > n_cbs) {
            min_work = n_cbs;
            thread_pool_index = id;
        }
    }

    {
        std::unique_lock<std::mutex> lock(thr_pool_.thread_list_[thread_pool_index]->lock_);

        thr_pool_.thread_list_[thread_pool_index]->exec_cbs_.push(cb);
        thr_pool_.thread_list_[thread_pool_index]->cond_.notify_all();
    }
}

int evt_mgr_intf::get_max_fd()
{
    int max_fd = 0;

    for (auto it : timer_list_) {
        if (it.fd_ > max_fd) {
            max_fd = it.fd_;
        }
    }

    for (auto it : socket_list_) {
        if (it.fd_ > max_fd) {
            max_fd = it.fd_;
        }
    }

    return max_fd;
}

void evt_mgr_intf::run()
{
    fd_set rdfd;
    uint64_t read_nsec;
    int max_fd;
    int ret;

    for (;;) {
        rdfd = allfd_;

        max_fd = get_max_fd();

        if (terminate_) {
            break;
        }

        ret = select(max_fd + 1, &rdfd, nullptr, nullptr, nullptr);
        if (ret > 0) {
            for (auto it : timer_list_) {
                if (FD_ISSET(it.fd_, &rdfd)) {
                    ret = read(it.fd_, &read_nsec, sizeof(read_nsec));
                    if (ret == sizeof(read_nsec)) {
                        it.cb_();
                    }
                    break;
                }
            }
            for (auto it : socket_list_) {
                if (FD_ISSET(it.fd_, &rdfd)) {
                    it.cb_(it.fd_);
                    break;
                }
            }
        } else {
            /**
             * We do not handle ret == 0 case because our timer pointer is
             * 0 and never happen to timeout.
            */
            break;
        }
    }
}

evt_mgr_intf::~evt_mgr_intf()
{
    for (auto it : timer_list_) {
        if (it.fd_ > 0) {
            close(it.fd_);
        }
    }
    timer_list_.clear();
    socket_list_.clear();
}

}
