#include <nos_logger.h>

int test_nos_logger()
{
    int var = 42;

    nos_log_set_log_level(NOS_LOG_LEVEL_VERBOSE);

    nos_log(NOS_LOG_SINK_CONSOLE,
            NOS_LOG_LEVEL_VERBOSE, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_CONSOLE,
            NOS_LOG_LEVEL_DEBUG, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_CONSOLE,
            NOS_LOG_LEVEL_INFO, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_CONSOLE,
            NOS_LOG_LEVEL_WARNING, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_CONSOLE,
            NOS_LOG_LEVEL_ERROR, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_CONSOLE,
            NOS_LOG_LEVEL_FATAL, "test log message %d\n", var);

    nos_log(NOS_LOG_SINK_LOGGER,
            NOS_LOG_LEVEL_VERBOSE, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_LOGGER,
            NOS_LOG_LEVEL_DEBUG, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_LOGGER,
            NOS_LOG_LEVEL_INFO, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_LOGGER,
            NOS_LOG_LEVEL_WARNING, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_LOGGER,
            NOS_LOG_LEVEL_ERROR, "test log message %d\n", var);
    nos_log(NOS_LOG_SINK_LOGGER,
            NOS_LOG_LEVEL_FATAL, "test log message %d\n", var);
    return 0;
}

int main()
{
    test_nos_logger();
}

