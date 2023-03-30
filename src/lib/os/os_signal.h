#ifndef __FW_LIB_OS_SIGNAL_H__
#define __FW_LIB_OS_SIGNAL_H__

#include <stdint.h>
#include <signal.h>

int os_block_signals(uint32_t *signals, uint32_t signals_size);
int os_block_term_signals();

#endif

