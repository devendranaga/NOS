#include <stdint.h>

int nos_fileio_open(const char *filename, const char *mode);
int nos_fileio_read(int fd, char *msg_out, uint32_t msg_size);
int nos_fileio_close(int fd);
