#ifndef __NOS_LOG_INTF_H__
#define __NOS_LOG_INTF_H__

#include <stdint.h>

enum log_msg_type {
    LOG_MSG_TYPE_LOGDATA,
    LOG_MSG_TYPE_CTRL,
};

enum log_msg_level {
    LOG_MSG_LEVEL_VERBOSE,
    LOG_MSG_LEVEL_DEBUG,
    LOG_MSG_LEVEL_INFO,
    LOG_MSG_LEVEL_WARN,
    LOG_MSG_LEVEL_ERROR,
    LOG_MSG_LEVEL_FATAL,
};

struct nos_log_data {
    uint8_t level;
    uint16_t len;
    uint8_t data[0];
} __attribute__ ((__packed__));

struct nos_log_intf {
    uint8_t type;
    uint16_t len;

    /* nos_log_data if type is LOG_MSG_TYPE_LOGDATA. */
    uint8_t data[0];
} __attribute__ ((__packed__));

#endif
