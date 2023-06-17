/**
 * @brief - Implements NOS logging interface.
*/
#ifndef __NOS_LOGGING_H__
#define __NOS_LOGGING_H__

namespace nos::core {

enum log_level {
    LOG_VERBOSE     = 0x0001,
    LOG_DEBUG       = 0x0002,
    LOG_INFO        = 0x0004,
    LOG_WARN        = 0x0008,
    LOG_ERR         = 0x0010,
    LOG_FATAL       = 0x0020,
};

class logging {
    public:
        explicit logging() = default;
        ~logging() = default;

        virtual void info(const char *msg, ...) = 0;
        virtual void warn(const char *msg, ...) = 0;
        virtual void err(const char *msg, ...) = 0;
        virtual void fatal(const char *msg, ...) = 0;
        virtual void verbose(const char *msg, ...) = 0;
        virtual void debug(const char *msg, ...) = 0;
        virtual void set_level(log_level log_lvl) = 0;
};

}

#endif
