#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <nos_logger.h>
#include <nos_logger_msg_intf.h>
#include <nos_socket.h>
#include <pthread.h>

static nos_log_level_t cur_log_lvl = NOS_LOG_LEVEL_INFO;
static int log_fd = -1;

static pthread_mutex_t lock;

static const char *nos_log_get_log_lvl_str(nos_log_level_t log_level)
{
    char *log_level_str = NULL;

    switch (log_level) {
        case NOS_LOG_LEVEL_VERBOSE:
            log_level_str = "verbose";
        break;
        case NOS_LOG_LEVEL_DEBUG:
            log_level_str = "debug";
        break;
        case NOS_LOG_LEVEL_INFO:
            log_level_str = "info";
        break;
        case NOS_LOG_LEVEL_WARNING:
            log_level_str = "warning";
        break;
        case NOS_LOG_LEVEL_ERROR:
            log_level_str = "error";
        break;
        case NOS_LOG_LEVEL_FATAL:
            log_level_str = "fatal";
        break;
        default:
            log_level_str = "unknown";
    }

    return log_level_str;
}

static int nos_log_console(nos_log_level_t log_level,
                           const char *fmt, va_list ap)
{
    const char *log_level_str = NULL;
    struct timespec tp;
    char buff[4096];
    struct tm *t;
    time_t now;
    int ret;

    log_level_str = nos_log_get_log_lvl_str(log_level);

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &tp);

    ret = snprintf(buff, sizeof(buff),
                    "[%04d-%02d-%02d %02d:%02d:%02d.%04ld] <%s> ",
                                t->tm_year + 1900,
                                t->tm_mon + 1,
                                t->tm_mday,
                                t->tm_hour,
                                t->tm_min,
                                t->tm_sec,
                                (tp.tv_nsec / 1000000U),
                                log_level_str);
    vsnprintf(buff + ret, sizeof(buff) - ret, fmt, ap);
    ret = fprintf(stderr, "%s", buff);

    return ret;
}

static int nos_logger_fill_log_data(nos_logger_msg_t *msg,
                                    nos_logger_log_lvl_t log_lvl,
                                    char *data, uint32_t data_len)
{
    nos_logger_log_data_t *log_data;

    msg->type = NOS_LOGGER_MSG_TYPE_LOG_DATA;
    msg->len = sizeof(nos_logger_log_data_t) + data_len;

    log_data = (nos_logger_log_data_t *)msg->val;
    log_data->log_lvl = log_lvl;
    memcpy(log_data->data, data, data_len);

    return sizeof(nos_logger_log_data_t) + msg->len;
}

static int nos_log_logger(nos_log_level_t log_level,
                          const char *fmt, va_list ap)
{
    nos_logger_msg_t *log_msg;
    char data[4096];
    uint8_t msg[4096];
    time_t now;
    struct tm *t;
    struct timespec tp;
    int ret;
    int len;
    const char *log_level_str;

    log_msg = (nos_logger_msg_t *)msg;

    if (log_fd < 0) {
        log_fd = nos_udp_client_init();
    }

    if (log_fd >= 0) {
        now = time(0);
        t = gmtime(&now);
        clock_gettime(CLOCK_REALTIME, &tp);

        log_level_str = nos_log_get_log_lvl_str(log_level);

        ret = snprintf(data, sizeof(data),
                        "[%04d-%02d-%02d %02d:%02d:%02d.%04ld] <%s> ",
                        t->tm_year + 1900,
                        t->tm_mon + 1,
                        t->tm_mday,
                        t->tm_hour,
                        t->tm_min,
                        t->tm_sec,
                        (tp.tv_nsec / 1000000U),
                        log_level_str);
        ret += vsnprintf(data - ret, sizeof(data) - ret, fmt, ap);

        len = nos_logger_fill_log_data(log_msg, log_level, data, ret);
        ret = nos_udp_socket_write(log_fd, msg, len,
                                   NOS_LOG_SERVICE_IP,
                                   NOS_LOG_SERVICE_PORT);
    }
    return ret;
}

static int nos_log_msg(nos_log_sink_t sink,
                       nos_log_level_t log_level,
                       const char *fmt, va_list ap)
{
    switch (sink) {
        case NOS_LOG_SINK_CONSOLE:
            return nos_log_console(log_level, fmt, ap);
        break;
        case NOS_LOG_SINK_LOGGER:
            return nos_log_logger(log_level, fmt, ap);
        break;
        default:
            return -1;
    }

    return -1;
}

int nos_log(nos_log_sink_t sink, nos_log_level_t log_level,
            const char *fmt, ...)
{
    va_list ap;
    int ret;

    if (log_level > cur_log_lvl) {
        return -1;
    }

    /*
     * This API can be called from multiple contexts and that
     * the internal data must be protected so that we can guarantee
     * the re-entrancy to print or log the proper messages without corruption.
     */
    pthread_mutex_lock(&lock);
    va_start(ap, fmt);
    ret = nos_log_msg(sink, log_level, fmt, ap);
    va_end(ap);
    pthread_mutex_unlock(&lock);

    return ret;
}

void nos_log_set_log_level(nos_log_level_t log_level)
{
    pthread_mutex_lock(&lock);
    cur_log_lvl = log_level;
    pthread_mutex_unlock(&lock);
}

