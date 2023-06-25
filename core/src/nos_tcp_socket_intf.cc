/**
 * @brief - Implements TCP socket interface.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <iostream>
#include <exception>
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

tcp_server::tcp_server(const std::string &ipaddr, int port, int n_conn) :
                        ipaddr_(ipaddr), port_(port), n_conn_(n_conn)
{
    struct sockaddr_in serv;
    int reuse_addr = 1;
    int ret;

    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to socket");
    }

    ret = setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
    if (ret < 0) {
        close(sock_);
        throw std::system_error(errno, std::generic_category(),
                                "failed to setsockopt");
    }
    serv.sin_addr.s_addr = inet_addr(ipaddr.c_str());
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = bind(sock_, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to bind");
    }

    ret = listen(sock_, n_conn);
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to listen");
    }
}

tcp_server::~tcp_server()
{
    if (sock_ > 0) {
        close(sock_);
    }
    sock_ = -1;
}

std::shared_ptr<tcp_conn> tcp_server::accept()
{
    struct sockaddr_in cli_addr;
    socklen_t cli_addr_len = sizeof(struct sockaddr_in);
    int conn_fd;
    int ret;
    char *ipaddr;
    int port;

    conn_fd = ::accept(sock_, (struct sockaddr *)&cli_addr, &cli_addr_len);
    if (conn_fd < 0) {
        return nullptr;
    }

    ipaddr = inet_ntoa(cli_addr.sin_addr);
    if (ipaddr) {
        return std::make_shared<tcp_conn>(conn_fd, ipaddr, port);
    } else {
        return nullptr;
    }
}

tcp_client::tcp_client(const std::string &ipaddr, int port) :
                        ipaddr_(ipaddr), port_(port)
{
    struct sockaddr_in serv;
    int reuse_addr = 1;
    int ret;

    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to socket");
    }

    serv.sin_addr.s_addr = inet_addr(ipaddr.c_str());
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = connect(sock_, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to bind");
    }
}

tcp_client::~tcp_client()
{
    if (sock_ > 0) {
        close(sock_);
    }
    sock_ = -1;
}

int tcp_client::send(const uint8_t *data, uint32_t data_len)
{
    return ::send(sock_, data, data_len, 0);
}

int tcp_client::recv(uint8_t *data, uint32_t data_len)
{
    return ::recv(sock_, data, data_len, 0);
}

tcp_unix_server::tcp_unix_server(const std::string &path, int n_conn) :
                                 path_(path), n_conn_(n_conn)
{
    struct sockaddr_un serv;
    int ret;

    sock_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_ < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to socket");
    }

    strcpy(serv.sun_path, path.c_str());
    serv.sun_family = AF_UNIX;
    ret = bind(sock_, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to bind");
    }

    ret = listen(sock_, n_conn);
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(),
                                 "failed to listen");
    }
}

std::shared_ptr<tcp_conn> tcp_unix_server::accept()
{
    struct sockaddr_un cli;
    socklen_t cli_len = sizeof(struct sockaddr_un);
    int ret;
    int conn_fd;

    conn_fd = ::accept(sock_, (struct sockaddr *)&cli, &cli_len);
    if (conn_fd < 0) {
        return nullptr;
    }

    return std::make_shared<tcp_conn>(conn_fd, cli.sun_path, 0);
}

tcp_unix_server::~tcp_unix_server()
{
    if (sock_ > 0) {
        close(sock_);
    }
    sock_ = -1;
}

tcp_unix_client::tcp_unix_client(const std::string &path) : path_(path)
{
    int ret;

    sock_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_ < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failed to socket");
    }

    struct sockaddr_un serv;
    strcpy(serv.sun_path, path.c_str());
    serv.sun_family = AF_UNIX;

    ret = connect(sock_, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "failedto connect");
    }
}

int tcp_unix_client::send(const uint8_t *data, uint32_t data_len)
{
    return ::send(sock_, data, data_len, 0);
}

int tcp_unix_client::recv(uint8_t *data, uint32_t data_len)
{
    return ::recv(sock_, data, data_len, 0);
}

tcp_unix_client::~tcp_unix_client()
{
    if (sock_ > 0) {
        close(sock_);
    }
    sock_ = -1;
}

}
