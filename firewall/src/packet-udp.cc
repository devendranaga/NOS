/**
 * @brief - Implements parsing udp header.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <packet.h>

#define RETURN_ON_ERR(__type) {\
    if (__type != event_type::NO_ERROR) {\
        return type;\
    }\
}

namespace nos::firewall
{

#define UDP_HDR_LEN_DEFAULT 8

event_type udp_header::deserialize(packet_buf &buf)
{
    event_type type;

    if (buf.remaining_bytes() < 8) {
        return event_type::UDP_INVALID_HDR_LEN;
    }

    type = buf.deserialize_2_bytes(&source_port);
    RETURN_ON_ERR(type);

    if (source_port == 0) {
        return event_type::UDP_SRC_PORT_IS_ZERO;
    }

    type = buf.deserialize_2_bytes(&dest_port);
    RETURN_ON_ERR(type);

    if (dest_port == 0) {
        return event_type::UDP_DEST_PORT_IS_ZERO;
    }

    type = buf.deserialize_2_bytes(&length);
    RETURN_ON_ERR(type);

    type = buf.deserialize_2_bytes(&checksum);
    RETURN_ON_ERR(type);

    return event_type::NO_ERROR;
}

}
