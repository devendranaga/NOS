#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <nos_tcp_socket_intf.h>

namespace nos::core
{

tcp_conn::~tcp_conn()
{
    if (sock_ > 0) {
        close(sock_);
    }
}

int tcp_conn::send(const uint8_t *data, uint32_t data_len)
{
    return ::send(sock_, data, data_len, 0);
}

int tcp_conn::recv(uint8_t *data, uint32_t data_size)
{
    return ::recv(sock_, data, data_size, 0);
}

}
