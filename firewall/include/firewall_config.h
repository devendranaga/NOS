/**
 * @brief - Defines firewall configuration.
 * 
 * @copyright - All rights reserved.
 * @author - Devendra Naga.
*/
#ifndef __NOS_FIREWALL_CONFIG_H__
#define __NOS_FIREWALL_CONFIG_H__

#include <string>
#include <vector>

namespace nos::firewall {

struct firewall_intf_config {
    std::string ifname;
    std::string rules_file;
};

enum event_format {
    Light,
    Full,
};

enum event_msg_format {
    v1,
};

enum event_protocol {
    udp,
    tcp,
};

struct event_upload_binary {
    bool enable;
    event_protocol protocol;
    std::string server_ip;
    int server_port;
};

struct event_upload_protobuf {
    bool enable;
    event_protocol protocol;
    std::string server_ip;
    int server_port;
};

struct event_upload_mqtt {
    bool enable;
    event_protocol protocol;
    std::string server_ip;
    int server_port;
    std::string event_topic;
};

struct event_uploads {
    event_upload_binary binary_cfg;
    event_upload_protobuf protobuf_cfg;
    event_upload_mqtt mqtt_cfg;
};

struct event_config {
    event_format evt_fmt;
    event_msg_format evt_msg_fmt;
    event_uploads evt_upload_cfg;
};

struct firewall_config {
    ~firewall_config() { }
    firewall_config(const firewall_config &) = delete;
    const firewall_config &operator=(const firewall_config &) = delete;

    static firewall_config *instance() {
        static firewall_config conf;
        return &conf;
    }
    std::vector<firewall_intf_config> intf_list_;
    event_config evt_conf_;

    public:
        explicit firewall_config() { }
};

}

#endif
