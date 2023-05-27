/**
 * @brief - Implements Event Manager.
 * 
 * @copyright - 2023 - present All rights reserved. Ask me for license.
 * @author - Devendra Naga
*/
#ifndef __NOS_EVT_MGR_H__
#define __NOS_EVT_MGR_H__

#include <unistd.h>
#include <sys/select.h>
#include <memory>
#include <functional>
#include <string>
#include <vector>

namespace nos::core::lib {

/* Timer callback type. */
typedef std::function<void(void)> timer_fn;

/* Socket callback type. */
typedef std::function<void(int)> socket_fn;

/* Signal callback type. */
typedef std::function<void(int)> signal_fn;

/**
 * Timer info defines the structure used by the timer context.
 */
struct timer_info {
    uint32_t sec;
    uint64_t nsec;
    timer_fn fn;
    bool oneshot;
    int timer_fd;
    int timer_id;

    explicit timer_info(uint32_t secs, uint64_t nsecs, timer_fn timer_cb, bool oneshot_timer) :
                sec(secs), nsec(nsecs), fn(timer_cb), oneshot(oneshot_timer) { }
    explicit timer_info() { }
    ~timer_info() { }
};

/**
 * Socket info defines the structure used by the socket context.
 */
struct socket_info {
    int fd;
    socket_fn fn;
    int socket_id;

    explicit socket_info(uint32_t sock, socket_fn socket_cb) :
                fd(sock), fn(socket_cb) { }
    explicit socket_info() { }
    ~socket_info() { }
};

struct timer_context {
    explicit timer_context() { }
    ~timer_context() { }

    /**
     * @brief - create timer and set the timeout.
     * 
     * @return 0 on success -1 on failure.
     */
    int create_timer(uint32_t sec, uint64_t n_sec, const timer_fn &fn, bool oneshot_timer);

    /**
     * @brief - Delete the created timer.
     * 
     * @return 0 on success -1 on failure.
     */
    int delete_timer(int timer_id);

    /**
     * @brief - Handle timer expiry.
     * 
     * @return 0 if callback is triggered -1 if not matched.
     */
    int handle_timer(fd_set &fds);

    std::vector<timer_info> timer_list_;
    int timer_id_cur_;
};

struct socket_context {
    explicit socket_context() { }
    ~socket_context() { }

    /**
     * @brief - Create socket.
     */
    int create_socket(int fd, const socket_fn &fn);

    /**
     * @brief - Delete socket.
     */
    int delete_socket(int socket_id);

    /**
     * @brief - Handle socket event.
     */
    int handle_socket(fd_set &fds);

    std::vector<socket_info> socket_list_;
    int socket_id_cur_;
};

struct signal_context {
    explicit signal_context() { }
    ~signal_context() { }

    int create_signal(const signal_fn &fn);
};

class evt_mgr {
    public:
        static evt_mgr *instance() {
            static evt_mgr mgr;
            return &mgr;
        }
        ~evt_mgr() { }

        /**
         * @brief - Register timer with the given timeout.
         * 
         * @return timer_id on success -1 on failure.
         */
        int register_timer(uint32_t sec, uint64_t nsec, const timer_fn &fn, bool oneshot = false);

        /**
         * @brief - Register socket with the given fd.
         * 
         * @return socket_id on success -1 on failure.
         */
        int register_socket(int fd, const socket_fn &fn);

        /**
         * @brief - Unregister a timer with the given timer_id.
         * 
         * @return 0 on success -1 on failure.
        */
        int unregister_timer(int timer_id);

        /**
         * @brief - Unregister a socket with the given socket_id.
         * 
         * @return 0 on success -1 on failure.
         */
        int unregister_socket(int socket_id);

        /**
         * @brief - Terminate the event mgr.
         */
        void terminate() { terminate_ = true; }

        /**
         * @brief - Run event mgr.
         */
        void run();

    private:
        explicit evt_mgr();
        int max_fd();
        bool terminate_;
        fd_set reg_fd_;
        timer_context timer_ctx_;
        socket_context socket_ctx_;
        signal_context signal_ctx_;
};

}

#endif
