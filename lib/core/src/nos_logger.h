
#ifdef __cplusplus
extern "C" {
#endif

typedef enum nos_log_level {
    NOS_LOG_LEVEL_FATAL,
    NOS_LOG_LEVEL_ERROR,
    NOS_LOG_LEVEL_WARNING,
    NOS_LOG_LEVEL_INFO,
    NOS_LOG_LEVEL_DEBUG,
    NOS_LOG_LEVEL_VERBOSE,
} nos_log_level_t;

typedef enum nos_log_sink {
    NOS_LOG_SINK_CONSOLE,
    NOS_LOG_SINK_LOGGER,
    NOS_LOG_SINK_SYSLOG,
} nos_log_sink_t;

int nos_log(nos_log_sink_t sink, nos_log_level_t log_level,
            const char *fmt, ...);

void nos_log_set_log_level(nos_log_level_t log_level);

#ifdef __cplusplus
}
#endif

