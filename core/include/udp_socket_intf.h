/**
 * @brief - Implements UDP Socket Interface.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_UDP_SOCKET_INTF_H__
#define __NOS_UDP_SOCKET_INTF_H__

#include <string>

namespace nos::core
{

/**
 * @brief - Implements UDP Server.
*/
class udp_server {
    public:
        explicit udp_server(const std::string &ipaddr, int port);
        ~udp_server();

        inline int get_socket() { return fd_; }
        int send(const uint8_t *msg, uint32_t msg_len,
                 const std::string &dest_ip, int dest_port);
        int recv(uint8_t *msg, uint32_t msg_len,
                 std::string &sender_ip, int *sender_port);

    private:
        int fd_;
};

/**
 * @brief - Implements UDP Client.
*/
class udp_client {
    public:
        explicit udp_client();
        ~udp_client();

        inline int get_socket() { return fd_; }
        int send(const uint8_t *msg, uint32_t msg_len,
                 const std::string &dest_ip, int dest_port);
        int recv(uint8_t *msg, uint32_t msg_len,
                 std::string &sender_ip, int *sender_port);

    private:
        int fd_;
};

/**
 * @brief - Implements UDP UNIX Server.
*/
class udp_unix_server {
    public:
        explicit udp_unix_server(const std::string &self_path);
        ~udp_unix_server();

        inline int get_socket() { return fd_; }
        int send(const uint8_t *msg, uint32_t msg_len,
                 const std::string &dest_path);
        int recv(uint8_t *msg, uint32_t msg_len,
                 std::string &sender_path);
    private:
        int fd_;
};

/**
 * @brief - Implements UDP UNIX Client.
*/
class udp_unix_client {
    public:
        explicit udp_unix_client(const std::string &self_path);
        ~udp_unix_client();

        inline int get_socket() { return fd_; }
        int send(const uint8_t *msg, uint32_t msg_len,
                 const std::string &dest_path);
        int recv(uint8_t *msg, uint32_t msg_len,
                 std::string &sender_path);
    private:
        int fd_;
};

}

#endif
