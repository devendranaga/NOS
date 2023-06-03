/**
 * @brief - Implements nos timestamp interface class.
 * 
 * @copyright - 2023-present All rights reserved.
 * @author - Devendra Naga.
*/
#ifndef __NOS_TIME_INTF_H__
#define __NOS_TIME_INTF_H__

#include <stdint.h>
#include <string>

namespace nos::core {

struct timestamp_cal {
    uint32_t year;
    uint32_t mon;
    uint32_t day;
    uint32_t hour;
    uint32_t min;
    uint32_t sec;
};

struct timestamp_ns {
    uint32_t sec;
    uint64_t nsec;
};

class time_intf {
    public:
        explicit time_intf() = default;
        ~time_intf() = default;

        int get_calendar(timestamp_cal &cal);
        int get_ns_monotonic(timestamp_ns &ns);
        int get_ns_realtime(timestamp_ns &ns);
        int sub(const timestamp_ns &new_ns,
                const timestamp_ns &old_ns,
                timestamp_ns &res);
        int make_timestamp(std::string &ts_fmt);
};

}

#endif
