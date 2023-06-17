/**
 * @brief - Implements File interface.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
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
    } else if (ops == file_ops::READ_WRITE) {
        fileops |= O_RDWR;
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

int file_intf::read_byte(uint8_t &byte)
{
    return ::read(fd_, &byte, sizeof(byte));
}

int file_intf::read_new_line(uint8_t *buf, uint32_t buf_size)
{
    int len = 0;
    int ret;

    while (1) {
        uint8_t byte;
        ret = ::read(fd_, &byte, sizeof(byte));
        if (ret < 0) {
            break;
        }

        printf("ret %d\n", ret);

        if (byte == '\n') {
            break;
        }

        buf[len] = byte;
        len ++;
    }

    buf[len] = '\0';
    return len;
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

static int copy_file(const std::string &src,
                     const std::string &dst)
{
    int src_fd;
    int dst_fd;

    src_fd = ::open(src.c_str(), O_RDONLY);
    if (src_fd < 0) {
        return -1;
    }

    dst_fd = ::open(dst.c_str(), O_CREAT | O_RDWR, S_IRWXU);
    if (dst_fd < 0) {
        return -1;
    }

    while (1) {
        uint8_t data[8192];
        int ret;

        ret = read(src_fd, data, sizeof(data));
        if (ret > 0) {
            write(dst_fd, data, ret);
        } else {
            break;
        }
    }

    close(src_fd);
    fsync(dst_fd);
    close(dst_fd);

    return 0;
}

int file_intf::copy(const std::string &src,
                    const std::string &dst)
{
    return copy_file(src, dst);
}

int file_intf::move(const std::string &src,
                    const std::string &dst)
{
    int ret;

    ret = copy_file(src, dst);
    if (ret == 0) {
        ret = remove(src.c_str());
    }

    return ret;
}

int file_intf::get_filesize(const std::string &filename,
                            uint32_t &filesize_bytes)
{
    struct stat t;
    int ret;

    ret = stat(filename.c_str(), &t);
    if (ret != 0) {
        return -1;
    }

    filesize_bytes = t.st_size;
    return 0;
}

bool file_intf::is_socket(const std::string &filename)
{
    struct stat mode;
    int ret;

    ret = stat(filename.c_str(), &mode);
    if (ret != 0) {
        return -1;
    }

    return ((mode.st_mode & S_IFMT) == S_IFSOCK);
}

bool file_intf::is_fifo(const std::string &filename)
{
    struct stat mode;
    int ret;

    ret = stat(filename.c_str(), &mode);
    if (ret != 0) {
        return -1;
    }

    return ((mode.st_mode & S_IFMT) == S_IFIFO);
}

void file_intf::flush()
{
    if (fd_ > 0) {
        fsync(fd_);
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
