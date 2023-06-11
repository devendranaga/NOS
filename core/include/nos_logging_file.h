/**
 * @brief - Implements Log File.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_LOGGING_FILE_H__
#define __NOS_LOGGING_FILE_H__

#include <stdarg.h>
#include <memory>
#include <nos_udp_socket_intf.h>
#include <nos_logging.h>

namespace nos::core
{

class nos_logging_file : public logging {
    public:
        explicit nos_logging_file() = default;
        ~nos_logging_file() = default;

        void info(const char *msg, ...);
        void warn(const char *msg, ...);
        void err(const char *msg, ...);
        void fatal(const char *msg, ...);
        void verbose(const char *msg, ...);
        void debug(const char *msg, ...);
        void set_level(log_level log_lvl);

    private:
        std::shared_ptr<udp_client> client_;
        log_level lvl_;
        void log_message(const char *fmt, log_level lvl, const char *log_format, va_list ap);
};

}

#endif
