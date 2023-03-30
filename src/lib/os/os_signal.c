#include <os_signal.h>

int os_block_signals(uint32_t *signals, uint32_t signals_size)
{
    sigset_t block;
    uint32_t i = 0;

    sigemptyset(&block);
    for (i = 0; i < signals_size; i ++) {
        sigaddset(&block, signals[i]);
    }

    return sigprocmask(SIG_BLOCK, &block, 0);
}

int os_block_term_signals()
{
    uint32_t signals[] = {SIGINT, SIGTERM};

    return os_block_signals(signals, sizeof(signals) / sizeof(signals[0]));
}

