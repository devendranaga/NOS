#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nos_socket.h>

#define ERR_RET_SOCKET(__fd) {\
    if (__fd < 0) {\
        close(__fd);\
        return -1;\
    }\
}

int nos_tcp_server_init(const char *ipaddr, int port, int n_conn)
{
    struct sockaddr_in serv;
    int reuse = 1;
    int ret;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    ERR_RET_SOCKET(fd);

    /* reuse socket. */
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    ERR_RET_SOCKET(fd);

    serv.sin_addr.s_addr = inet_addr(ipaddr);
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = bind(fd, (struct sockaddr *)&serv, sizeof(serv));
    ERR_RET_SOCKET(fd);

    ret = listen(fd, n_conn);
    ERR_RET_SOCKET(fd);

    return fd;
}

int nos_tcp_client_init(const char *ipaddr, int port);
int nos_tcp_server_accept(int fd, char *client_ipaddr, int *client_port);
int nos_tcp_socket_read(int fd, uint8_t *data, uint32_t data_len);
int nos_tcp_socket_write(int fd, uint8_t *data, uint32_t data_len);
int nos_tcp_close(int fd);

int nos_udp_server_init(const char *ipaddr, int port);
int nos_udp_client_init(int fd);
int nos_udp_socket_read(int fd, uint8_t *data, uint32_t data_len,
                        char *dest_addr, int dest_port);
int nos_udp_socket_write(int fd, uint8_t *data, uint32_t data_len,
                         char *dest_addr, int dest_port);
int nos_udp_close(int fd);


