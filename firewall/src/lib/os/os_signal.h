#ifndef __FW_LIB_OS_SIGNAL_H__
#define __FW_LIB_OS_SIGNAL_H__

#include <stdint.h>
#include <signal.h>
#include <firewall_common.h>

void os_register_signal(const uint32_t signum, void (*callback)(int signum));
void os_register_signals(const uint32_t *signals, uint32_t signals_size,
                         void (*callback)(int signum));
int os_block_signals(const uint32_t *signals, uint32_t signals_size);
int os_block_term_signals();

#endif

