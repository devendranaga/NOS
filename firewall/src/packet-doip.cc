#include <packet.h>

namespace nos::firewall
{

event_type doip_header::deserialize(packet_buf &buf,
                                    const std::shared_ptr<nos::core::logging> &log)
{
    buf.deserialize_byte(&version);
    buf.deserialize_byte(&inv_version);

    /* Version and Inverse Version did not match. */
    if (version != inv_version) {
        return event_type::DOIP_VERSION_INV_VERSION_MISMATCH;
    }

    buf.deserialize_2_bytes(&type);
    buf.deserialize_4_bytes(&len);

    if (type == DOIP_TYPE_VEH_ANNOUNCEMENT) {
        buf.deserialize_bytes(announcement.vin, sizeof(announcement.vin));
        buf.deserialize_2_bytes(&announcement.logical_addr);
        buf.deserialize_bytes(announcement.eid, sizeof(announcement.eid));
        buf.deserialize_bytes(announcement.gid, sizeof(announcement.gid));
        buf.deserialize_byte(&announcement.further_action_required);
    }

    return event_type::NO_ERROR;
}

}

