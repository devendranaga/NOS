#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <nos_file_intf.h>

namespace nos::core {

static uint32_t get_filemode(const file_mode &mode)
{
    uint32_t mode_val = 0;

    if (mode & file_mode::USR_READ) {
        mode_val |= S_IRUSR;
    }
    if (mode & file_mode::USR_WRITE) {
        mode_val |= S_IWUSR;
    }
    if (mode & file_mode::USR_EXEC) {
        mode_val |= S_IXUSR;
    }
    if (mode & file_mode::GROUP_READ) {
        mode_val |= S_IRGRP;
    }
    if (mode & file_mode::GROUP_WRITE) {
        mode_val |= S_IWGRP;
    }
    if (mode & file_mode::GROUP_EXEC) {
        mode_val |= S_IXGRP;
    }
    if (mode & file_mode::OTHERS_READ) {
        mode_val |= S_IROTH;
    }
    if (mode & file_mode::OTHERS_WRITE) {
        mode_val |= S_IWOTH;
    }
    if (mode & file_mode::OTHERS_EXEC) {
        mode_val |= S_IXOTH;
    }

    return mode_val;
}

int file_intf::create(const std::string &filename, const file_mode &mode)
{
    uint32_t mode_val = get_filemode(mode);

    fd_ = ::open(filename.c_str(), O_CREAT | O_RDWR, mode_val);
    if (fd_ < 0) {
        return -1;
    }

    return fd_;
}

int file_intf::open(const std::string &filename, const file_ops &ops)
{
    uint32_t fileops = 0;

    if (ops& file_ops::READ) {
        fileops |= O_RDONLY;
    } else if (ops == file_ops::WRITE) {
        fileops |= O_WRONLY;
    } else if (ops == file_ops::APPEND) {
        fileops |= O_RDWR | O_APPEND;
    } else {
        return -1;
    }

    fd_ = ::open(filename.c_str(), fileops);
    if (fd_ < 0) {
        return -1;
    }

    return fd_;
}

int file_intf::read(uint8_t *buf, uint32_t buf_len)
{
    return ::read(fd_, buf, buf_len);
}

int file_intf::write(const uint8_t *buf, uint32_t buf_len)
{
    return ::write(fd_, buf, buf_len);
}

void file_intf::close()
{
    if (fd_ > 0) {
        fsync(fd_);
        ::close(fd_);
        fd_ = -1;
    }
}

file_intf::file_intf()
{
    fd_ = -1;
}

file_intf::~file_intf()
{
    if (fd_ > 0) {
        fsync(fd_);
        ::close(fd_);
        fd_ = -1;
    }
}

}
