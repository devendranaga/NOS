#include <stdint.h>

int aos_fileio_open(const char *filename, const char *mode);
int aos_fileio_read(int fd, char *msg_out, uint32_t msg_size);
int aos_fileio_close(int fd);
