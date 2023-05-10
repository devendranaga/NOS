#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nos_socket.h>

#define ERR_RET_SOCKET(__res) {\
    if (__res < 0) {\
        close(__res);\
        return -1;\
    }\
}

int nos_tcp_server_init(const char *ipaddr, uint32_t port, uint32_t n_conn)
{
    struct sockaddr_in serv;
    int reuse = 1;
    int ret;
    int fd;

    if (!ipaddr || (port == 0) || (n_conn == 0)) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    ERR_RET_SOCKET(fd);

    /* reuse socket. */
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    ERR_RET_SOCKET(ret);

    serv.sin_addr.s_addr = inet_addr(ipaddr);
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = bind(fd, (struct sockaddr *)&serv, sizeof(serv));
    ERR_RET_SOCKET(ret);

    ret = listen(fd, n_conn);
    ERR_RET_SOCKET(ret);

    return fd;
}

int nos_tcp_client_init(const char *ipaddr, uint32_t port)
{
    struct sockaddr_in serv;
    int ret;
    int fd;

    if (!ipaddr || (port == 0)) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    ERR_RET_SOCKET(fd);

    serv.sin_addr.s_addr = inet_addr(ipaddr);
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = connect(fd, (struct sockaddr *)&serv, sizeof(serv));
    ERR_RET_SOCKET(ret);

    return fd;
}

int nos_tcp_server_accept(int fd, char *client_ipaddr, int *client_port)
{
    struct sockaddr_in conn;
    socklen_t len = sizeof(struct sockaddr_in);
    char *conn_addr;
    int client_fd;

    client_fd = accept(fd, (struct sockaddr *)&conn, &len);
    ERR_RET_SOCKET(client_fd);

    conn_addr = inet_ntoa(conn.sin_addr);
    if (conn_addr)
        strcpy(client_ipaddr, conn_addr);

    *client_port = htons(conn.sin_port);

    return client_fd;
}

int nos_tcp_socket_read(int fd, uint8_t *data, uint32_t data_len)
{
    return recv(fd, data, data_len, 0);
}

int nos_tcp_socket_write(int fd, uint8_t *data, uint32_t data_len)
{
    return send(fd, data, data_len, 0);
}

void nos_tcp_close(int fd)
{
    if (fd > 0) {
        close(fd);
    }
}

int nos_udp_server_init(const char *ipaddr, int port);
int nos_udp_client_init(int fd);
int nos_udp_socket_read(int fd, uint8_t *data, uint32_t data_len,
                        char *dest_addr, int dest_port);
int nos_udp_socket_write(int fd, uint8_t *data, uint32_t data_len,
                         char *dest_addr, int dest_port);
int nos_udp_close(int fd);


