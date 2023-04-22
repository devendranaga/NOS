/**
 * @brief - Implements OS routines.
 *
 * @author Devendra Naga (devendra.aaru@outlook.com).
 * @copyright 2023-present All rights reserved.
 */
#ifndef __FW_OS_H__
#define __FW_OS_H__

/**
 * @brief - Wait for the timeout.
 *
 * @param [in] timeout - timeout in milliseconds.
 *
 * @return 0 on success.
 */
int os_wait_for_timeout(uint32_t);

#endif

