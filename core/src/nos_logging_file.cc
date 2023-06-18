/**
 * @brief - Implements log to a file via socket.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <nos_logging_file.h>
#include <nos_log_msg_intf.h>

namespace nos::core
{

#define SERVER_IP_ADDR "127.0.0.1"
#define SERVER_PORT 1441

void nos_logging_file::log_message(const char *fmt, log_level log_lvl, const char *log_format, va_list ap)
{
    char msg[2048];
    time_t now = 0;
    struct tm *t;
    struct timespec tp;
    nos_log_intf *log_intf;
    nos_log_data *log_data;
    int remaining_len;
    int ret;

    if (!client_) {
        client_ = std::make_shared<udp_client>();
    }
    log_intf = (nos_log_intf *)msg;
    log_data = (nos_log_data *)log_intf->data;

    log_intf->type = LOG_MSG_TYPE_LOGDATA;
    log_data->level = (log_msg_level)log_lvl;

    remaining_len = sizeof(msg) - sizeof(nos_log_intf) - sizeof(nos_log_data);

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &tp);
    ret = snprintf((char *)log_data->data, remaining_len, "[%04d-%02d-%02d %02d:%02d:%02d.%04lu ] <%s> ",
                                     t->tm_year + 1900, t->tm_mon + 1,
                                     t->tm_mday, t->tm_hour,
                                     t->tm_min, t->tm_sec,
                                     tp.tv_nsec / 1000000UL, log_format);
    ret += vsnprintf((char *)log_data->data + ret, remaining_len - ret, fmt, ap);

    log_data->len = ret;
    log_intf->len = ret + sizeof(nos_log_intf) +
                    sizeof(log_data->level) +
                    sizeof(log_data->len);

    if (client_) {
        client_->send((const uint8_t *)msg,
                      log_intf->len + sizeof(nos_log_intf),
                      SERVER_IP_ADDR, SERVER_PORT);
    }
}

void nos_logging_file::info(const char *fmt, ...)
{
    va_list ap;

    if (lvl_ & log_level::LOG_INFO) {
        va_start(ap, fmt);
        log_message(fmt, log_level::LOG_INFO, "Info", ap);
        va_end(ap);
    }
}

void nos_logging_file::warn(const char *fmt, ...)
{
    va_list ap;

    if (lvl_ & log_level::LOG_WARN) {
        va_start(ap, fmt);
        log_message(fmt, log_level::LOG_WARN, "Warn", ap);
        va_end(ap);
    }
}

void nos_logging_file::err(const char *fmt, ...)
{
    va_list ap;

    if (lvl_ & log_level::LOG_ERR) {
        va_start(ap, fmt);
        log_message(fmt, log_level::LOG_ERR, "Err", ap);
        va_end(ap);
    }
}

void nos_logging_file::fatal(const char *fmt, ...)
{
    va_list ap;

    if (lvl_ & log_level::LOG_FATAL) {
        va_start(ap, fmt);
        log_message(fmt, log_level::LOG_FATAL, "Fatal", ap);
        va_end(ap);
    }
}

void nos_logging_file::verbose(const char *fmt, ...)
{
    va_list ap;

    if (lvl_ & log_level::LOG_VERBOSE) {
        va_start(ap, fmt);
        log_message(fmt, log_level::LOG_VERBOSE, "Verbose", ap);
        va_end(ap);
    }
}

void nos_logging_file::debug(const char *fmt, ...)
{
    va_list ap;

    if (lvl_ & log_level::LOG_DEBUG) {
        va_start(ap, fmt);
        log_message(fmt, log_level::LOG_DEBUG, "Debug", ap);
        va_end(ap);
    }
}

void nos_logging_file::set_level(log_level log_lvl)
{
    lvl_ = log_lvl;
}

}
