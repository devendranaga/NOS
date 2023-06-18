#include <nos_core.h>

static void log_data(std::shared_ptr<nos::core::logging> &logger)
{
    if (logger) {
        NOS_LOG_INFO(logger, "info log\n");
        NOS_LOG_WARN(logger, "warn log\n");
        NOS_LOG_ERR(logger, "err log\n");
        NOS_LOG_DEBUG(logger, "debug log\n");
        NOS_LOG_FATAL(logger, "fatal log\n");
        NOS_LOG_VERBOSE(logger, "verbose log\n");
    }
}

int test_logger()
{
    std::shared_ptr<nos::core::logging> logger;

    logger = NOS_LOG_INTF_CONSOLE();
    log_data(logger);

    logger = NOS_LOG_INTF_FILE();
    log_data(logger);

    return 0;
}
