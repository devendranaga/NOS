#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <string>
#include <nos_logging_console.h>

namespace nos::core {

static void log_msg_console(const char *fmt,
                            const std::string &log_level,
                            va_list ap)
{
    char msg[2048];
    time_t now;
    struct tm *t;
    struct timespec tp;
    int len;

    now = time(0);
    t = gmtime(&now);

    clock_gettime(CLOCK_REALTIME, &tp);

    len = snprintf(msg, sizeof(msg), "[%04d-%02d-%02d %02d:%02d:%02d.%04lu] <%s> ",
                                t->tm_year + 1900, t->tm_mon + 1,
                                t->tm_mday, t->tm_hour,
                                t->tm_min, t->tm_sec,
                                tp.tv_nsec / 1000000ul, log_level.c_str());
    len = vsnprintf(msg + len, sizeof(msg) - len, fmt, ap);
    fprintf(stderr, "%s", msg);
}

void console_logging::info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg_console(fmt, "Info", ap);
    va_end(ap);
}

void console_logging::warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg_console(fmt, "Warn", ap);
    va_end(ap);
}

void console_logging::err(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg_console(fmt, "Error", ap);
    va_end(ap);
}

void console_logging::fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg_console(fmt, "Fatal", ap);
    va_end(ap);
}

void console_logging::verbose(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg_console(fmt, "Verbose", ap);
    va_end(ap);
}

void console_logging::debug(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg_console(fmt, "Debug", ap);
    va_end(ap);
}

void console_logging::set_level(log_level log_lvl)
{
    log_lvl_ = log_lvl;
}

}
