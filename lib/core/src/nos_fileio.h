#ifndef __NOS_FILEIO_H__
#define __NOS_FILEIO_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int nos_fileio_open(const char *filename, const char *mode);
int nos_fileio_read(int fd, uint8_t *msg_out, uint32_t msg_size);
int nos_fileio_sync(int fd);
int nos_fileio_write(int fd, uint8_t *msg_out, uint32_t msg_size);
void nos_fileio_close(int fd);
int nos_fileio_get_filesize(const char *filename);

#ifdef __cplusplus
}
#endif

#endif

