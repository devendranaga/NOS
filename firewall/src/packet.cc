#include <packet.h>

namespace nos::firewall {

#define BOUNDS_CHECK_AND_FAIL(__off, __requested, __len) {\
    if (__off + __requested > __len) {\
        return event_type::PACKET_LEN_TOO_SHORT;\
    }\
}

event_type packet_buf::deserialize_byte(uint8_t *byte)
{
    *byte = data[off];
    BOUNDS_CHECK_AND_FAIL(off, 1, data_len);

    off ++;

    return event_type::NO_ERROR;
}

}