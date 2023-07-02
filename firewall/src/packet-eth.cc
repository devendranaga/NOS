#include <packet.h>

namespace nos::firewall {

event_type ether_header::deserialize(packet_buf &buf,
                                     const std::shared_ptr<nos::core::logging> &log)
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

    print(log);

    return type;
}

void ether_header::print(const std::shared_ptr<nos::core::logging> &log)
{
    log->debug("eth_hdr: {\n");
    log->debug("\t src: [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                        srcmac[0], srcmac[1],
                        srcmac[2], srcmac[3],
                        srcmac[4], srcmac[5]);
    log->debug("\t dst: [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                        dstmac[0], dstmac[1],
                        dstmac[2], dstmac[3],
                        dstmac[4], dstmac[5]);
    log->debug("}\n");
}

}
