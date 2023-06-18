/**
 * @brief - Implements nos Log factory.
 */
#ifndef __NOS_LOG_FACTORY_H__
#define __NOS_LOG_FACTORY_H__

#include <memory>
#include <nos_logging.h>
#include <nos_logging_console.h>
#include <nos_logging_file.h>

namespace nos::core {

enum logger_type {
    Console,
    Dlt,
    File,
};

class log_factory {
    public:
        ~log_factory() { }
        log_factory(const log_factory &) = delete;
        log_factory(const log_factory &&) = delete;
        const log_factory &operator=(const log_factory &) = delete;
        const log_factory &&operator=(const log_factory &&) = delete;

        /**
         * @brief - Get an instance of log_factory.
        */
        static log_factory *instance() {
            static log_factory f;
            return &f;
        }

        /**
         * @brief - Create logger interface.
        */
        std::shared_ptr<logging> create(logger_type type)
        {
            if (type == logger_type::Console) {
                return std::make_shared<console_logging>();
            } else if (type == logger_type::File) {
                return std::make_shared<nos_logging_file>();
            }

            return nullptr;
        }

    private:
        explicit log_factory() { }
};

#define NOS_LOG_INTF_NEW(__type) \
    nos::core::log_factory::instance()->create(__type)
#define NOS_LOG_INTF_CONSOLE() \
    nos::core::log_factory::instance()->create(nos::core::logger_type::Console)
#define NOS_LOG_INTF_FILE() \
    nos::core::log_factory::instance()->create(nos::core::logger_type::File)

#define NOS_LOG_INFO(__log, __fmt, ...) __log->info(__fmt, ##__VA_ARGS__)
#define NOS_LOG_WARN(__log, __fmt, ...) __log->warn(__fmt, ##__VA_ARGS__)
#define NOS_LOG_ERR(__log, __fmt, ...) __log->err(__fmt, ##__VA_ARGS__)
#define NOS_LOG_FATAL(__log, __fmt, ...) __log->fatal(__fmt, ##__VA_ARGS__)
#define NOS_LOG_VERBOSE(__log, __fmt, ...) __log->verbose(__fmt, ##__VA_ARGS__)
#define NOS_LOG_DEBUG(__log, __fmt, ...) __log->debug(__fmt, ##__VA_ARGS__)

#define NOS_LOG_TRACE_START(__log, __fmt)\
    __log->verbose("%s: %s:%u\n", __fmt, __func__, __LINE__)

}

#endif
