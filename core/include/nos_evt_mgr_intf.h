/**
 * @brief - Implements Event Manager.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
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

namespace nos::core
{

/**
 * Timer callback.
*/
typedef std::function<void(void)> timer_cb;

/**
 * Socket callback.
*/
typedef std::function<void(int)> socket_cb;

/**
 * Executor callback.
*/
typedef std::function<void(void)> exec_cb;

/**
 * socket interface with corresponding, id, fd and callback.
*/
struct evt_socket_intf {
    socket_cb cb_;
    int id_;
    int fd_;
};

/**
 * Timer interface to capture corresponding timer information and callback.
*/
struct evt_timer_intf {
    timer_cb cb_;
    int id_;
    bool oneshot_;
    uint32_t sec_;
    uint64_t nsec_;
    int fd_;
};

/**
 * Thread related information.
*/
struct evt_thread {
    std::mutex lock_;
    std::condition_variable cond_;
    std::queue<exec_cb> exec_cbs_;
    std::shared_ptr<std::thread> thread_;

    explicit evt_thread();
    ~evt_thread();

    /**
     * Executes the callbacks in sequence one by one.
    */
    void thread_func();
};

/**
 * Threadpool structure with  info about each thread.
*/
struct evt_thread_pool_intf {
    int n_threads_;
    std::vector<std::shared_ptr<evt_thread>> thread_list_;
};

/**
 * Event Manager configuration.
*/
struct evt_mgr_config {
    int n_threads;
};

/**
 * Defines the event manager interface class for applications.
 * 
 * This is a singleton so that applications can call to get an instance
 * to register for events at any time or path.
*/
class evt_mgr_intf {
    public:
        ~evt_mgr_intf();
        evt_mgr_intf(const evt_mgr_intf &) = delete;
        evt_mgr_intf(const evt_mgr_intf &&) = delete;
        const evt_mgr_intf &operator=(const evt_mgr_intf &) = delete;
        const evt_mgr_intf &&operator=(const evt_mgr_intf &&) = delete;

        /**
         * @brief - get an instance of the evt_mgr_intf
        */
        static evt_mgr_intf *instance() {
            static evt_mgr_intf intf;
            return &intf;
        }

        /**
         * @brief - initialize the evt_mgr_intf
         * 
         * @return 0 on success -1 on failure.
        */
        int init(const evt_mgr_config &conf);

        /**
         * @brief - register a timer and fire the callback upon the timeout.
         * 
         * @return timer_id on success -1 on failure.
        */
        int register_timer(uint32_t sec, uint64_t nsec, timer_cb cb, bool oneshot);

        /**
         * @brief - unregister a timer with given timer id.
        */
        void unregister_timer(int id);

        /**
         * @brief - register a socket and fire the callback upon data reception.
         * 
         * @return socket_id on success -1 on failure.
        */
        int register_socket(int fd, socket_cb cb);

        /**
         * @brief - unregister a socket with given socket id.
        */
        void unregister_socket(int id);

        /**
         * @brief - queue the work to one of the threads. The work is queued and
         * will be called synchronously.
        */
        void queue_work(const exec_cb &cb);

        /**
         * @brief - run the whole event manager.
        */
        void run();

        /**
         * @brief - terminate the event manager.
        */
        void terminate() { terminate_ = true; }
    private:
        explicit evt_mgr_intf() { }
        int get_max_fd();
        std::vector<evt_timer_intf> timer_list_;
        std::vector<evt_socket_intf> socket_list_;
        evt_thread_pool_intf thr_pool_;
        evt_mgr_config conf_;
        bool terminate_;
        fd_set allfd_;
        int timer_id_;
        int socket_id_;
};

}

#endif

