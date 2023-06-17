/**
 * @brief - Implements File Interface.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_FILE_INTF_H__
#define __NOS_FILE_INTF_H__

#include <stdint.h>
#include <string>

namespace nos::core
{

enum file_mode {
    USR_READ        = 0x00000001,
    USR_WRITE       = 0x00000002,
    USR_EXEC        = 0x00000004,
    GROUP_READ      = 0x00000008,
    GROUP_WRITE     = 0x00000010,
    GROUP_EXEC      = 0x00000020,
    OTHERS_READ     = 0x00000040,
    OTHERS_WRITE    = 0x00000080,
    OTHERS_EXEC     = 0x00000100,
    MODE_SECURITY   = USR_READ | USR_WRITE,
    MODE_ALL        = USR_READ | USR_WRITE | USR_EXEC |
                      GROUP_READ | GROUP_WRITE | GROUP_EXEC |
                      OTHERS_READ | OTHERS_WRITE | OTHERS_EXEC,
    MODE_NOEXEC     = USR_READ | USR_WRITE |
                      GROUP_READ | GROUP_WRITE |
                      OTHERS_READ | OTHERS_WRITE,
    MODE_LINUX      = USR_READ | USR_WRITE |
                      GROUP_READ |
                      OTHERS_READ,
};

enum file_ops {
    READ            = 0x00000001,
    WRITE           = 0x00000002,
    READ_WRITE      = READ | WRITE,
    APPEND          = 0x00000004,
};

class file_intf {
    public:
        explicit file_intf();
        ~file_intf();

        int create(const std::string &filename, const file_mode &mode);
        int open(const std::string &filename, const file_ops &ops);
        int read(uint8_t *buf, uint32_t buf_len);
        int read_byte(uint8_t &byte);
        int read_new_line(uint8_t *buf, uint32_t buf_len);
        int write(const uint8_t *buf, uint32_t buf_len);
        int copy(const std::string &source_file,
                 const std::string &target_file);
        int move(const std::string &source_file,
                 const std::string &target_file);
        int get_filesize(const std::string &filename, uint32_t &filesize_bytes);
        bool is_socket(const std::string &filename);
        bool is_fifo(const std::string &filename);
        bool is_file_opened() { return fd_ >= 0; }
        int remove(const std::string &filename);
        void flush();
        void close();

    private:
        int fd_;
};

}

#endif

