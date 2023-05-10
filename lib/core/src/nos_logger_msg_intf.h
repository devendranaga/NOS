#include <stdint.h>

typedef enum nos_logger_log_lvl {
    NOS_LOGGER_LOG_LVL_VERBOSE,
    NOS_LOGGER_LOG_LVL_DEBUG,
    NOS_LOGGER_LOG_LVL_INFO,
    NOS_LOGGER_LOG_LVL_WARNING,
    NOS_LOGGER_LOG_LVL_ERROR,
    NOS_LOGGER_LOG_LVL_FATAL,
} nos_logger_log_lvl_t;

typedef enum nos_logger_msg_type {
    NOS_LOGGER_MSG_TYPE_LOG_DATA,
} nos_logger_msg_type_t;

typedef struct nos_logger_log_data {
    uint8_t log_lvl;
    uint8_t data[0];
} __attribute__ ((__packed__)) nos_logger_log_data_t;

typedef struct nos_logger_msg {
    uint8_t type;
    uint16_t len;
    uint8_t val[0];
} __attribute__ ((__packed__)) nos_logger_msg_t;
