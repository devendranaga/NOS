#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <nos_logger.h>
#include <pthread.h>

static nos_log_level_t cur_log_lvl = NOS_LOG_LEVEL_INFO;

static pthread_mutex_t lock;

static int nos_log_console(nos_log_level_t log_level,
                           const char *fmt, va_list ap)
{
    char *log_level_str = NULL;
    struct timespec tp;
    char buff[4096];
    struct tm *t;
    time_t now;
    int ret;

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
            return -1;
    }

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

static int nos_log_logger(nos_log_level_t log_level,
                          const char *fmt, va_list ap)
{
    return -1;
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

