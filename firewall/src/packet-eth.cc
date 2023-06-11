#include <packet.h>

namespace nos::firewall {

event_type ether_header::deserialize(packet_buf &buf)
{
    event_type type;

    type = buf.deserilaize_mac(srcmac);
    if (type != event_type::NO_ERROR) {
        return type;
    }
    type = buf.deserilaize_mac(dstmac);
    if (type != event_type::NO_ERROR) {
        return type;
    }
    type = buf.deserialize_2_bytes(&ethertype);
    if (type != event_type::NO_ERROR) {
        return type;
    }

    return type;
}

void ether_header::print()
{
    
}

}
