#ifndef __NOS_EVENT_TYPES_H__
#define __NOS_EVENT_TYPES_H__

namespace nos::firewall {

enum event_type {
    NO_ERROR,
    ETH_DESERIALIZE_FAILED,
    ARP_DESERIALIZE_FAILED,
    ARP_INVAL_ARP_OPERATION,
    ARP_HEADER_LEN_TOO_SHORT,
    ARP_HWADDR_LEN_INVAL,
    PACKET_LEN_TOO_SHORT,
};

}

#endif
