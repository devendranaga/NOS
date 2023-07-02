#include <packet.h>

namespace nos::firewall
{

event_type tcp_header::deserialize(packet_buf &buf,
                                   const std::shared_ptr<nos::core::logging> &log)
{
    event_type type;
    uint16_t opt_len;

    buf.deserialize_2_bytes(&source_port);
    buf.deserialize_2_bytes(&dest_port);
    buf.deserialize_4_bytes(&seq_no);
    buf.deserialize_4_bytes(&ack_no);
    hdr_len = (buf.data[buf.off] & 0xF0) >> 4;
    flags.reserved = (buf.data[buf.off] & 0x0E) >> 1;
    flags.ecn = !!(buf.data[buf.off] & 0x01);
    buf.off ++;

    flags.cwr = !!(buf.data[buf.off] & 0x80);
    flags.ecn_echo = !!(buf.data[buf.off] & 0x40);
    flags.urg = !!(buf.data[buf.off] & 0x20);
    flags.ack = !!(buf.data[buf.off] & 0x10);
    flags.psh = !!(buf.data[buf.off] & 0x08);
    flags.rst = !!(buf.data[buf.off] & 0x04);
    flags.syn = !!(buf.data[buf.off] & 0x02);
    buf.off ++;

    if (flags.all_zero()) {
        return event_type::TCP_ALL_FLAGS_ARE_ZERO;
    }

    buf.deserialize_2_bytes(&window);
    buf.deserialize_2_bytes(&checksum);
    buf.deserialize_2_bytes(&urg_ptr);

    opt_len = (hdr_len * 4 - TCP_HDR_LEN_MIN);
    while (opt_len > 0) {
        uint8_t opt_type = buf.data[buf.off];

        buf.off ++;

        contains_options = true;

        switch (opt_type) {
            case TCP_OPT_MSS: {
                buf.deserialize_byte(&opt.mss.len);
                buf.deserialize_2_bytes(&opt.mss.mss);
            } break;
            default:
                return event_type::TCP_OPT_UNSUPPORTED;
        }
    }

    return event_type::NO_ERROR;
}

}
