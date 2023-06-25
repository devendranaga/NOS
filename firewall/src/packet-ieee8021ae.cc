#include <cstdint>
#include <cstring>
#include <packet.h>

namespace nos::firewall
{

event_type ieee8021ae_header::deserialize(packet_buf &buf)
{
    tci.version = !!(buf.data[buf.off] & 0x80);
    if (tci.version != 0) {
        return event_type::MACSEC_INVAL_VERSION;
    }

    tci.es = !!(buf.data[buf.off] & 0x40);
    tci.sc = !!(buf.data[buf.off] & 0x20);
    tci.scb = !!(buf.data[buf.off] & 0x10);
    if (tci.sc && tci.scb) {
        return event_type::MACSEC_INVAL_SCI_SCB;
    }
    tci.e = !!(buf.data[buf.off] & 0x08);
    tci.c = !!(buf.data[buf.off] & 0x04);
    if (tci.c) {
        return event_type::MACSEC_INVAL_C;
    }
    tci.an = (buf.data[buf.off] & 0x03);

    buf.off ++;

    buf.deserialize_byte(&short_len);
    buf.deserialize_4_bytes(&pkt_no);
    buf.deserilaize_mac(sci.mac);
    buf.deserialize_2_bytes(&sci.port_id);

    std::memcpy(icv,
                buf.data + buf.data_len - MACSEC_ICV_LEN, MACSEC_ICV_LEN);
    /**
     * We reduce the remaining buffer by 16 as its an ICV.
    */
    buf.data_len -= MACSEC_ICV_LEN;

    return event_type::NO_ERROR;
}

}
