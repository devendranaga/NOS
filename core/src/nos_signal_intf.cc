/**
 * @brief - Implements Signal interface.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <nos_signal_intf.h>

namespace nos::core
{

signal_intf::signal_intf() { }
signal_intf::~signal_intf() { }

int signal_intf::block_signal(const std::vector<uint32_t> &signals)
{
    sigset_t set;

    sigemptyset(&set);
    for (auto it : signals) {
        sigaddset(&set, it);
    }

    return sigprocmask(SIG_BLOCK, &set, nullptr);
}

int signal_intf::block_term_signals()
{
    std::vector<uint32_t> signals = {SIGINT, SIGTERM};

    return block_signal(signals);
}

}
