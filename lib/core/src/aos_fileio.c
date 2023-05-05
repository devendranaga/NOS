#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

int aos_fileio_open(const char *filename, const char *mode)
{
    int fd;

    if (mode == "rb") {
        fd = open(filename, O_RDONLY);
        if (fd < 0) {
            return -1;
        }
    }

    return fd;
}

int aos_fileio_read(int fd, char *msg_out, uint32_t msg_size)
{
    return read(fd, msg_out, msg_size);
}

int aos_fileio_close(int fd)
{
    if (fd > 0) {
        close(fd);
    }
}
