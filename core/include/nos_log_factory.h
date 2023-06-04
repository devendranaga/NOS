#ifndef __NOS_LOG_FACTORY_H__
#define __NOS_LOG_FACTORY_H__

#include <memory>
#include <logger.h>
#include <nos_logging_console.h>

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

        static log_factory *instance() {
            static log_factory f;
            return &f;
        }

        std::shared_ptr<logging> create(logger_type type)
        {
            if (logger_type::Console) {
                return std::make_shared<console_logging>();
            }

            return nullptr;
        }

    private:
        explicit log_factory() { }
};

}

#endif
