#include <nos_core.h>

int test_logger()
{
    std::shared_ptr<nos::core::logging> logger;

    logger = nos::core::log_factory::instance()->create(
                       nos::core::logger_type::Console);

    if (logger) {
        logger->info("info log\n");
        logger->warn("warn log\n");
        logger->err("err log\n");
        logger->debug("debug log\n");
        logger->fatal("fatal log\n");
        logger->verbose("verbose log\n");
    }

    return 0;
}
