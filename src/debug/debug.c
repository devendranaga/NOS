#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <debug.h>
#include <time.h>
#include <sys/time.h>
#include <firewall_common.h>

STATIC struct fw_debug_level_ctl {
    fw_debug_level_t debug_level;
    bool enabled;
} debug_ctl_set[] = {
    {FW_DEBUG_LEVEL_VERBOSE, true},
    {FW_DEBUG_LEVEL_INFO, true},
    {FW_DEBUG_LEVEL_WARN, true},
    {FW_DEBUG_LEVEL_ERROR, true},
    {FW_DEBUG_LEVEL_FATAL, true},
};

STATIC bool is_log_lvl_enabled(fw_debug_level_t level)
{
    return debug_ctl_set[level].enabled;
}

/* Write log data to the output. */
STATIC void fw_debug_msg(fw_debug_level_t debug_level,
                         const char *fmt, va_list ap)
{
    struct timespec tp;
    char msg[4096];
    struct tm *t;
    time_t now;
    int len = 0;

    /* Drop if log level not present. */
    if (is_log_lvl_enabled(debug_level) == false) {
        return;
    }

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &tp);

    len = snprintf(msg, sizeof(msg),
                    "[%04d-%02d-%02d %02d:%02d:%02d:%04llu] ",
                    t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                    t->tm_hour, t->tm_min, t->tm_sec,
                    tp.tv_nsec / 1000000ULL);

    switch (debug_level) {
        case FW_DEBUG_LEVEL_VERBOSE:
            len += snprintf(msg + len, sizeof(msg) - len, "<verbose> ");
        break;
        case FW_DEBUG_LEVEL_INFO:
            len += snprintf(msg + len, sizeof(msg) - len, "<info> ");
        break;
        case FW_DEBUG_LEVEL_WARN:
            len += snprintf(msg + len, sizeof(msg) - len, "<warning> ");
        break;
        case FW_DEBUG_LEVEL_ERROR:
            len += snprintf(msg + len, sizeof(msg) - len, "<error> ");
        break;
        case FW_DEBUG_LEVEL_FATAL:
            len += snprintf(msg + len, sizeof(msg) - len, "<fatal> ");
        break;
    }

    len += vsnprintf(msg + len, sizeof(msg) - len, fmt, ap);
    fprintf(stderr, "%s", msg);
}

void fw_debug(fw_debug_level_t debug_level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fw_debug_msg(debug_level, fmt, ap);
    va_end(ap);
}

void fw_debug_set_log_level(fw_debug_level_t debug_level)
{
    debug_ctl_set[debug_level].enabled = true;
}

void fw_debug_clear_log_level(fw_debug_level_t debug_level)
{
    debug_ctl_set[debug_level].enabled = false;
}

