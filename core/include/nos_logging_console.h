#ifndef __NOS_LOGGING_CONSOLE_H__
#define __NOS_LOGGING_CONSOLE_H__

#include <nos_logging.h>

namespace nos::core {

class console_logging : public logging {
    public:
        explicit console_logging() {
            log_lvl_ = (log_level)(log_level::LOG_INFO |
                                 log_level::LOG_WARN |
                                 log_level::LOG_ERR |
                                 log_level::LOG_FATAL);
        }
        ~console_logging() = default;

        void info(const char *msg, ...);
        void warn(const char *msg, ...);
        void err(const char *msg, ...);
        void fatal(const char *msg, ...);
        void verbose(const char *msg, ...);
        void debug(const char *msg, ...);
        void set_level(log_level log_lvl);

    private:
        log_level log_lvl_;
};

}

#endif
