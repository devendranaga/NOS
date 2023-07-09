/**
 * @brief - Implements nos_utils.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
 */
#include <string.h>
#include <nos_utils.h>
#include <arpa/inet.h>

namespace nos::core
{

int convert_mac(const std::string &val_str, uint8_t *mac)
{
    uint32_t mac_buf[6];
    int ret;

    if (!mac) {
        return -1;
    }

    ret = sscanf(val_str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                        &mac_buf[0], &mac_buf[1], &mac_buf[2],
                        &mac_buf[3], &mac_buf[4], &mac_buf[5]);
    if (ret != 6) {
        return -1;
    }

    mac[0] = mac_buf[0];
    mac[1] = mac_buf[1];
    mac[2] = mac_buf[2];
    mac[3] = mac_buf[3];
    mac[4] = mac_buf[4];
    mac[5] = mac_buf[5];

    return 0;
}

int convert_to_int(const std::string &val_str, int *val_int)
{
    char *err = nullptr;

    if (!val_int) {
        return -1;
    }

    *val_int = strtol(val_str.c_str(), &err, 10);
    if (err && (*err != '\0')) {
        return -1;
    }

    return 0;
}

int convert_to_uint(const std::string &val_str, uint32_t *val_uint)
{
    char *err = nullptr;

    if (!val_uint) {
        return -1;
    }

    *val_uint = strtoul(val_str.c_str(), &err, 10);
    if (err && (*err != '\0')) {
        return -1;
    }

    return 0;
}

int convert_to_hex(const std::string &val_str, uint32_t *val_hex)
{
    char *err = nullptr;

    if (!val_hex) {
        return -1;
    }

    *val_hex = strtoul(val_str.c_str(), &err, 16);
    if (err && (*err != '\0')) {
        return -1;
    }

    return 0;
}

int convert_to_ipv4(const std::string &val_str, uint32_t *ipv4)
{
    struct in_addr addr;
    int ret;

    ret = inet_aton(val_str.c_str(), &addr);
    if (ret == 1) {
        *ipv4 = addr.s_addr;
        ret = 0;
    } else {
        ret = -1;
    }

    return ret;
}

}
