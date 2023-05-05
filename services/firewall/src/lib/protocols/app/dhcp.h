/**
 * @brief - Implement DHCP header parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_DHCP_H__
#define __LIB_PROTOCOLS_DHCP_H__

#include <stdint.h>

#define DHCP_MAGIC_COOKIE "DHCP"

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_INFORM   8

#define DHCP_MSG_TYPE_BOOT_REQ                              1

#define DHCP_OPT_MESSAGE_TYPE                               53
#define DHCP_OPT_CLIENT_ID                                  61
#define DHCP_OPT_HOST_NAME                                  12
#define DHCP_OPT_VENDOR_CLASS_ID                            60
#define DHCP_OPT_PARAMETER_REQ_LIST                         55

#define DHCP_OPT_PARAMETER_SUBNET_MASK                      1
#define DHCP_OPT_PARAMETER_ROUTER                           3
#define DHCP_OPT_PARAMETER_DOMAIN_NAME_SERVER               6
#define DHCP_OPT_PARAMETER_DOMAIN_NAME                      15
#define DHCP_OPT_PARAMETER_PERFORM_ROUTER_DISCOVERY         31
#define DHCP_OPT_PARAMETER_STATIC_ROUTE                     33
#define DHCP_OPT_PARAMETER_VENDOR_SPECIFIC                  43
#define DHCP_OPT_PARAMETER_NETBIOS_OVER_TCP_IP_NAME_SERVER  44
#define DHCP_OPT_PARAMETER_NETBIOS_OVER_TCP_IP_NODE_TYPE    46
#define DHCP_OPT_PARAMETER_NETBIOS_OVER_TCP_IP_SCOPE        47
#define DHCP_OPT_PARAMETER_DHCP_SERVER_IDENTIFIER           54
#define DHCP_OPT_PARAMETER_CLASSLESS_STATIC_ROUTE           121
#define DHCP_OPT_PARAMETER_PRIVATE_ROUTE                    249
#define DHCP_OPT_PARAMETER_PRIVATE_AUTO_DISCOVERY           252
#define DHCP_OPT_PARAMETER_END                              255

struct dhcp_opt_server_identifier {
    uint32_t ipaddr;
};

struct dhcp_opt_subnet_mask {
    uint32_t subnet_mask;
};

struct dhcp_opt_router {
    uint32_t router_ipaddr;
};

struct dhcp_opt_dns_list {
    uint32_t n_servers;
    uint32_t *dns_server_ipaddr;
};

struct dhcp_opt_domain_name {
    char *name;
};

struct dhcp_opt_client_identifier {
    uint8_t hw_type;
    uint8_t client_mac[6];
};

struct dhcp_hostname {
    uint8_t hostname_len;
    uint8_t *hostname;
};

struct dhcp_vendor_class_id {
    uint8_t len;
    uint8_t *id;
};

struct dhcp_parameter_request_list {
    uint8_t len;
    uint8_t *parameter_list;
};

struct dhcp_options {
    uint8_t dhcp_inform;
    struct dhcp_opt_client_identifier client_id;
    struct dhcp_opt_server_identifier server_id;
    struct dhcp_hostname hostname;
    struct dhcp_vendor_class_id vendor;
    struct dhcp_parameter_request_list param_list;
    struct dhcp_opt_subnet_mask subnet_mask;
    struct dhcp_opt_router router;
    struct dhcp_opt_dns_list dns_list;
    struct dhcp_opt_domain_name domain_name;
    uint8_t dhcp_end;
};

struct dhcp_header {
    uint8_t message_type;
    uint8_t hardware_type;
    uint8_t hardware_address_len;
    uint8_t hops;
    uint8_t transaction_id[4];
    uint16_t seconds_elapsed;
    bool bootp_broadcast_flag;
    uint16_t reserved;
    uint32_t client_ipaddr;
    uint32_t your_ipaddr;
    uint32_t next_server_ipaddr;
    uint32_t relay_agent_ipaddr;
    uint8_t client_mac[6];
    uint8_t client_padding[10];
    uint8_t server_hostname[64];
    uint8_t boot_filename[128];
    uint8_t magic_cookie[4];
    struct dhcp_options options;
};

typedef struct dhcp_header dhcp_header_t;

#endif

