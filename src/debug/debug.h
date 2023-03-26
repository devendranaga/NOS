#ifndef __FW_DEBUG_H__
#define __FW_DEBUG_H__

struct fw_debug_context {
};

enum fw_debug_level {
    FW_DEBUG_LEVEL_VERBOSE,
    FW_DEBUG_LEVEL_INFO,
    FW_DEBUG_LEVEL_WARN,
    FW_DEBUG_LEVEL_ERROR,
    FW_DEBUG_LEVEL_FATAL,
};

typedef enum fw_debug_level fw_debug_level_t;

void fw_debug(fw_debug_level_t debug_level, const char *fmt, ...);
void fw_debug_set_log_level(fw_debug_level_t debug_level);
void fw_debug_clear_log_level(fw_debug_level_t debug_level);

#endif

