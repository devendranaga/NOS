#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <file_intf.h>

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

    fd_ = ::open(filename.c_str(), O_CREAT, O_RDWR | mode);
    if (fd_ < 0) {
        return -1;
    }

    return fd_;
}

}