#include <os_signal.h>

void os_register_signal(CONST uint32_t signum, void (*callback)(int signum))
{
    signal(signum, callback);
}

void os_register_signals(const uint32_t *signals, uint32_t signals_size,
                         void (*callback)(int signum))
{
    uint32_t i = 0;

    for (i = 0; i < signals_size; i ++) {
        os_register_signal(signals[i], callback);
    }
}

int os_block_signals(const uint32_t *signals, uint32_t signals_size)
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
    const uint32_t signals[] = {SIGINT, SIGTERM};

    return os_block_signals(signals, sizeof(signals) / sizeof(signals[0]));
}

