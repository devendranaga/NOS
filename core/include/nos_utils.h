/**
 * @brief - Implements utility functions.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __NOS_UTILS_H__
#define __NOS_UTILS_H__

#include <cstdint>
#include <string>

namespace nos::core
{

/**
 * @brief - convert to int.
 *
 * @param[in] val_str: string to convert
 * @param[inout] val_int: converted integer.
 *
 * @return 0 on success -1 on failure.
 */
int convert_to_int(const std::string &val_str, int *val_int);

/**
 * @brief - convert to uint.
 *
 * @param[in] val_str: string to convert
 * @param[inout] val_uint: converted integer.
 *
 * @return 0 on success -1 on failure.
 */
int convert_to_uint(const std::string &val_str, uint32_t *val_uint);

/**
 * @brief - convert mac address.
 *
 * @param[in] val_str: string to convert.
 * @param[inout] mac: converted mac.
 *
 * @return 0 on success -1 on failure.
 */
int convert_mac(const std::string &val_str, uint8_t *mac);

/**
 * @brief - convert to hex.
 *
 * @param[in] val_str: string to convert.
 * @param[input] val_hex: converted hex.
 *
 * @return 0 on success -1 on failure.
 */
int convert_to_hex(const std::string &val_str, uint32_t *val_hex);

/**
 * @broef - convert to ipv4.
 *
 * @param[in] val_str: string to convert.
 * @param[inout] ipv4: converted ipv4.
 *
 * @return 0 on success -1 on failure.
 */
int convert_to_ipv4(const std::string &val_str, uint32_t *ipv4);

}

#endif
