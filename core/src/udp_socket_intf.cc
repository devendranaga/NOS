/**
 * @brief - Implements UDP Socket Interface.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <iostream>
#include <exception>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <udp_socket_intf.h>

namespace nos::core
{

udp_server::udp_server(const std::string &ipaddr, int port)
{
    int reuseaddr = 1;
    int ret;

    fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to socket");
    }

    ret = setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (ret < 0) {
        close(fd_);
        throw std::system_error(errno, std::generic_category(), "failed to setsockopt");
    }

    struct sockaddr_in serv;

    serv.sin_addr.s_addr = inet_addr(ipaddr.c_str());
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;
    ret = bind(fd_, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to bind");
    }
}

udp_server::~udp_server()
{
    if (fd_ > 0) {
        close(fd_);
    }
}

int udp_server::send(const uint8_t *msg, uint32_t msg_len,
                     const std::string &dest_ip, int dest_port)
{
    struct sockaddr_in dest;

    dest.sin_addr.s_addr = inet_addr(dest_ip.c_str());
    dest.sin_port = htons(dest_port);
    dest.sin_family = AF_INET;

    return sendto(fd_, msg, msg_len, 0, (struct sockaddr *)&dest, sizeof(dest));
}

int udp_server::recv(uint8_t *msg, uint32_t msg_len,
                     std::string &sender_ip, int *sender_port)
{
    struct sockaddr_in sender;
    char *sender_ip_str;
    socklen_t sender_len = 0;
    int ret;

    ret = recvfrom(fd_, msg, msg_len, 0, (struct sockaddr *)&sender, &sender_len);
    if (ret < 0) {
        return -1;
    }

    sender_ip_str = inet_ntoa(sender.sin_addr);
    sender_ip = std::string(sender_ip_str);
    *sender_port = htons(sender.sin_port);

    return ret;
}

udp_client::udp_client()
{
    fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to socket");
    }
}

udp_client::~udp_client()
{
    if (fd_ > 0) {
        close(fd_);
    }
}

int udp_client::send(const uint8_t *msg, uint32_t msg_len,
                     const std::string &dest_ip, int dest_port)
{
    struct sockaddr_in dest;

    dest.sin_addr.s_addr = inet_addr(dest_ip.c_str());
    dest.sin_port = htons(dest_port);
    dest.sin_family = AF_INET;

    return sendto(fd_, msg, msg_len, 0, (struct sockaddr *)&dest, sizeof(dest));
}

int udp_client::recv(uint8_t *msg, uint32_t msg_len,
                     std::string &sender_ip, int *sender_port)
{
    struct sockaddr_in sender;
    socklen_t sender_len;
    char *sender_addr;
    int ret;

    sender_len = sizeof(struct sockaddr_in);

    ret = recvfrom(fd_, msg, msg_len, 0, (struct sockaddr *)&sender, &sender_len);
    if (ret < 0) {
        return -1;
    }

    sender_addr = inet_ntoa(sender.sin_addr);
    sender_ip = std::string(sender_addr);
    *sender_port = htons(sender.sin_port);

    return ret;
}

udp_unix_server::udp_unix_server(const std::string &self_path)
{
    fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to socket");
    }
}

udp_unix_server::~udp_unix_server()
{
    if (fd_ > 0) {
        close(fd_);
    }
}

int udp_unix_server::send(const uint8_t *msg, uint32_t msg_len,
                          const std::string &dest_path)
{
    struct sockaddr_un dest;
    int len;

    strcpy(dest.sun_path, dest_path.c_str());
    dest.sun_family = AF_UNIX;

    len = dest_path.length() + sizeof(dest.sun_family);

    return sendto(fd_, msg, msg_len, 0, (struct sockaddr *)&dest, len);
}

int udp_unix_server::recv(uint8_t *msg, uint32_t msg_len,
                          std::string &sender_path)
{
    struct sockaddr_un sender;
    socklen_t len;
    int ret;

    len = sizeof(struct sockaddr_un);
    ret = recvfrom(fd_, msg, msg_len, 0, (struct sockaddr *)&sender, &len);
    if (ret < 0) {
        return -1;
    }

    sender_path = std::string(sender.sun_path);

    return ret;
}

udp_unix_client::udp_unix_client(const std::string &self_path)
{
    fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to socket");
    }
}

udp_unix_client::~udp_unix_client()
{
    if (fd_ > 0) {
        close(fd_);
    }
}

int udp_unix_client::send(const uint8_t *msg, uint32_t msg_len,
                          const std::string &dest_path)
{
    struct sockaddr_un dest;
    int len;

    strcpy(dest.sun_path, dest_path.c_str());
    dest.sun_family = AF_UNIX;

    len = dest_path.length() + sizeof(dest.sun_family);

    return sendto(fd_, msg, msg_len, 0, (struct sockaddr *)&dest, len);
}

int udp_unix_client::recv(uint8_t *msg, uint32_t msg_len,
                          std::string &sender_path)
{
    struct sockaddr_un sender;
    socklen_t len;
    int ret;

    len = sizeof(struct sockaddr_un);
    ret = recvfrom(fd_, msg, msg_len, 0, (struct sockaddr *)&sender, &len);
    if (ret < 0) {
        return -1;
    }

    sender_path = sender.sun_path;
    return ret;
}

}
