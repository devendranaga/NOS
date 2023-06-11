/**
 * @brief - Implements nos timestamp interface.
 * 
 * @copyright - 2023-present All rights reserved.
 * @author - Devendra Naga.
*/
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <nos_time_intf.h>

namespace nos::core {

int time_intf::get_calendar(timestamp_cal &cal)
{
    struct tm *t;
    time_t now = time(0);

    t = gmtime(&now);
    if (!t) {
        return -1;
    }

    cal.year = t->tm_year + 1900;
    cal.mon = t->tm_mon + 1;
    cal.day = t->tm_mday;
    cal.hour = t->tm_hour;
    cal.min = t->tm_min;
    cal.sec = t->tm_sec;

    return 0;
}

int time_intf::get_ns_monotonic(timestamp_ns &ns)
{
    struct timespec tp;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &tp);
    if (ret != 0) {
        return -1;
    }

    ns.sec = tp.tv_sec;
    ns.nsec = tp.tv_nsec;

    return 0;
}

int time_intf::get_ns_realtime(timestamp_ns &ns)
{
    struct timespec tp;
    int ret;

    ret = clock_gettime(CLOCK_REALTIME, &tp);
    if (ret != 0) {
        return -1;
    }

    ns.sec = tp.tv_sec;
    ns.nsec = tp.tv_nsec;

    return 0;
}

int time_intf::make_timestamp(std::string &ts_fmt)
{
    char ts[1024] = {0};
    time_t now = time(0);
    struct timespec tp;
    struct tm *t;
    int ret;

    t = gmtime(&now);
    if (!t) {
        return -1;
    }

    ret = clock_gettime(CLOCK_REALTIME, &tp);
    if (ret != 0) {
        return -1;
    }

    snprintf(ts, sizeof(ts), "%04d_%02d_%02d_%02d_%02d_%02d.%04lu",
                    t->tm_year + 1900, t->tm_mon + 1,
                    t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
                    tp.tv_nsec / 1000000u);
    return 0;
}

}
