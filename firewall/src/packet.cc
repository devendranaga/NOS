#include <cstring>
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

event_type packet_buf::deserialize_2_bytes(uint16_t *val)
{
    BOUNDS_CHECK_AND_FAIL(off, 2, data_len);
    *val = data[off + 1] | (data[off] << 8);

    off += 2;

    return event_type::NO_ERROR;
}

event_type packet_buf::deserialize_4_bytes(uint32_t *val)
{
    BOUNDS_CHECK_AND_FAIL(off, 4, data_len);
    *val = (data[off + 3] >> 24) | (data[off + 2] >> 16) |
           (data[off + 1] >> 8) | (data[off]);
    off += 4;

    return event_type::NO_ERROR;
}

event_type packet_buf::deserialize_8_bytes(uint64_t *val)
{
    BOUNDS_CHECK_AND_FAIL(off, 8, data_len);
    *val = (((uint64_t)(data[off + 7]) >> 56) |
            ((uint64_t)(data[off + 6]) >> 48) |
            ((uint64_t)(data[off + 5]) >> 40) |
            ((uint64_t)(data[off + 4]) >> 32) |
            (data[off + 3] >> 24) |
            (data[off + 2] >> 16) |
            (data[off + 1] >> 8)  |
            (data[off]));
    off += 8;

    return event_type::NO_ERROR;
}

event_type packet_buf::deserilaize_mac(uint8_t *mac)
{
    BOUNDS_CHECK_AND_FAIL(off, MACADDR_LEN, data_len);
    std::memcpy(mac, data + off, MACADDR_LEN);

    off += 6;
    return event_type::NO_ERROR;
}

event_type packet_buf::deserialize_ipaddr(uint32_t *ipaddr)
{
    return deserialize_4_bytes(ipaddr);
}

event_type packet_buf::deserialize_ip6addr(uint8_t *ip6addr)
{
    BOUNDS_CHECK_AND_FAIL(off, 16, data_len);
    std::memcpy(ip6addr, data + off, 16);

    off += 16;
    return event_type::NO_ERROR;
}

event_type packet_buf::deserialize_bytes(uint8_t *bytes, uint32_t len)
{
    BOUNDS_CHECK_AND_FAIL(off, len, data_len);
    std::memcpy(bytes, data + off, len);

    off += len;
    return event_type::NO_ERROR;
}

}
