#include <packet.h>

namespace nos::firewall {

#define VALIDATE_AND_FAIL(__type) {\
    if (__type != event_type::NO_ERROR) {\
        return __type;\
    }\
}

event_type arp_header::deserialize(packet_buf &buf)
{
    event_type type;

    if ((buf.data_len - buf.off) < ARP_HEADER_LEN) {
        return event_type::ARP_HEADER_LEN_TOO_SHORT;
    }

    type = buf.deserialize_2_bytes(&header_type);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_2_bytes(&protocol_type);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_byte(&hwaddr_len);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_byte(&protoaddr_len);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_2_bytes(&operation);
    VALIDATE_AND_FAIL(type);

    if ((operation < ARP_OP_ARP_REQ) || (operation > ARP_OP_INARP_REPLY)) {
        return event_type::ARP_INVAL_ARP_OPERATION;
    }

    type = buf.deserilaize_mac(sender_hwaddr);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_4_bytes(&sender_proto_addr);
    VALIDATE_AND_FAIL(type);

    type = buf.deserilaize_mac(target_hwaddr);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_4_bytes(&target_proto_addr);
    VALIDATE_AND_FAIL(type);

    return type;
}

}
