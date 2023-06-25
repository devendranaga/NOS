/**
 * @brief -  Implements Signal interface.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __NOS_SIGNAL_INTF_H__
#define __NOS_SIGNAL_INTF_H__

#include <signal.h>
#include <cstdint>
#include <vector>

namespace nos::core
{

class signal_intf {
    public:
        explicit signal_intf();
        ~signal_intf();

        int block_signal(const std::vector<uint32_t> &signals);
        int block_term_signals();
};

}

#endif
