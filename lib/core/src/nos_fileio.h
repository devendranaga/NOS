#ifndef __NOS_FILEIO_H__
#define __NOS_FILEIO_H__

#include <stdint.h>

int nos_fileio_open(const char *filename, const char *mode);
int nos_fileio_read(int fd, char *msg_out, uint32_t msg_size);
void nos_fileio_close(int fd);

#endif

