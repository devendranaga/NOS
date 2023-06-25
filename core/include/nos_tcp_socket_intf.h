/**
 * @brief - Defines TCP socket interface.
*/
#ifndef __NOS_TCP_SOCKET_INTF_H__
#define __NOS_TCP_SOCKET_INTF_H__

#include <string>
#include <memory>

namespace nos::core
{

/**
 * @brief - Defines a connection structure that is returned by Accept
*/
class tcp_conn {
    public:
        explicit tcp_conn(int sock, const std::string &ipaddr, int port) : 
                            sock_(sock), ipaddr_(ipaddr), port_(port) { }
        explicit tcp_conn();
        ~tcp_conn();

        int get_socket() { return sock_; }

        int send(const uint8_t *data, uint32_t data_len);
        int recv(uint8_t *data, uint32_t data_size);

    private:
        int sock_;
        std::string ipaddr_;
        int port_;
};

/**
 * @brief - Defines a tcp server class.
*/
class tcp_server {
    public:
        explicit tcp_server(const std::string &ipaddr, int port, int n_conn);
        ~tcp_server();

        int get_socket() { return sock_; }

        std::shared_ptr<tcp_conn> accept();
    private:
        int sock_;
        std::string ipaddr_;
        int port_;
        int n_conn_;
};

/**
 * @brief - Defines a tcp client class.
*/
class tcp_client {
    public:
        explicit tcp_client(const std::string &ipaddr, int port);
        ~tcp_client();

        int get_socket() { return sock_; }

        int send(const uint8_t *data, uint32_t data_len);
        int recv(uint8_t *data, uint32_t data_size);

    private:
        int sock_;
        std::string ipaddr_;
        int port_;
};

/**
 * @brief - Defines a tcp unix server class.
*/
class tcp_unix_server {
    public:
        explicit tcp_unix_server(const std::string &path);
        ~tcp_unix_server();

        int get_socket() { return sock_; }

        int send(const uint8_t *data, uint32_t data_len);
        int recv(uint8_t *data, uint32_t data_size);

    private:
        int sock_;
        std::string path_;
};

/**
 * @brief - Defines a tcp unix client class.
*/
class tcp_unix_client {
    public:
        explicit tcp_unix_client(const std::string &path);
        ~tcp_unix_client();

        int get_socket() { return sock_; }

        int send(const uint8_t *data, uint32_t data_len);
        int recv(uint8_t *data, uint32_t data_size);

    private:
        int sock_;
        std::string path_;
};

}

#endif
