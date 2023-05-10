#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

int nos_fileio_open(const char *filename, const char *mode)
{
    int fd = -1;

    if (strcmp(mode, "rb") == 0) {
        fd = open(filename, O_RDONLY);
    } else if (strcmp(mode, "wb") == 0) {
        fd = open(filename, O_CREAT, O_RDWR | S_IRWXU);
    }

    return fd;
}

int nos_fileio_read(int fd, uint8_t *msg_out, uint32_t msg_size)
{
    return read(fd, msg_out, msg_size);
}

int nos_fileio_write(int fd, uint8_t *msg_out, uint32_t msg_size)
{
    return write(fd, msg_out, msg_size);
}

void nos_fileio_close(int fd)
{
    if (fd > 0) {
        close(fd);
    }
}
