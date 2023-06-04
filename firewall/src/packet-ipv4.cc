#include <packet.h>

namespace nos::firewall {

#define VALIDATE_AND_FAIL(__type) {\
    if (__type != event_type::NO_ERROR) {\
        return __type;\
    }\
}

#define BOUNDS_CHECK_AND_FAIL(__off, __len) {\
    if (__off > __len) {\
        return event_type::PACKET_LEN_TOO_SHORT;\
    }\
}

static int ipv4_validate_checksum()
{
    return 0;
}

event_type ipv4_header::deserialize(packet_buf &buf)
{
    event_type type;

    version = (buf.data[buf.off] & 0xF0) >> 4;
    if (version != IPV4_VERSION) {
        return event_type::IPV4_VERSION_INVAL;
    }

    ihl = (buf.data[buf.off] & 0x0F);
    if ((ihl < IPV4_IHL_LEN_MIN) || (ihl > IPV4_IHL_LEN_MAX)) {
        return event_type::IPV4_IHL_INVAL;
    }

    buf.off ++;

    dscp = (buf.data[buf.off] & 0xFC) >> 2;
    ecn = (buf.data[buf.off] & 0x03);

    type = buf.deserialize_2_bytes(&total_len);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_2_bytes(&id);
    VALIDATE_AND_FAIL(type);

    BOUNDS_CHECK_AND_FAIL(buf.off, buf.data_len);

    flags_reserved = !!(buf.data[buf.off] & 0x80);
    if (flags_reserved) {
        return event_type::IPV4_RESERVED_FLAG_SET;
    }

    flags_dont_fragment = !!(buf.data[buf.off] & 0x40);
    flags_more_fragment = !!(buf.data[buf.off] & 0x20);

    if (flags_more_fragment & flags_dont_fragment) {
        return event_type::IPV4_MF_DF_FLAGS_SET;
    }

    frag_off = ((buf.data[buf.off] & 0x1F) << 3) |
                (buf.data[buf.off + 1]);

    buf.off += 2;

    type = buf.deserialize_byte(&ttl);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_byte(&protocol);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_2_bytes(&hdr_chksum);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_4_bytes(&source_ipaddr);
    VALIDATE_AND_FAIL(type);

    type = buf.deserialize_4_bytes(&dest_ipaddr);
    VALIDATE_AND_FAIL(type);

    return event_type::NO_ERROR;
}

}
