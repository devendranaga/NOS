#ifndef __NOS_SOCKET_H__
#define __NOS_SOCKET_H__

#include <stdint.h>

int nos_tcp_server_init(const char *ipaddr, uint32_t port, uint32_t n_conn);
int nos_tcp_client_init(const char *ipaddr, uint32_t port);
int nos_tcp_server_accept(int fd, char *client_ipaddr, int *client_port);
int nos_tcp_socket_read(int fd, uint8_t *data, uint32_t data_len);
int nos_tcp_socket_write(int fd, uint8_t *data, uint32_t data_len);
void nos_tcp_close(int fd);

int nos_udp_server_init(const char *ipaddr, int port);
int nos_udp_client_init(int fd);
int nos_udp_socket_read(int fd, uint8_t *data, uint32_t data_len,
                        char *dest_addr, int dest_port);
int nos_udp_socket_write(int fd, uint8_t *data, uint32_t data_len,
                         char *dest_addr, int dest_port);
int nos_udp_close(int fd);

#endif

