#ifndef __NOS_PACKET_TCP_H__
#define __NOS_PACKET_TCP_H__

#include <stdint.h>
#include <string.h>
#include <event_types.h>
#include <packet-buf.h>
#include <nos_core.h>

namespace nos::firewall
{

#define TCP_HDR_LEN_MIN 20
#define TCP_HDR_LEN_MAX 60

#define TCP_OPT_MSS     2

struct tcp_flags {
    uint8_t reserved:3;
    bool ecn;
    bool cwr;
    bool ecn_echo;
    bool urg;
    bool ack;
    bool psh;
    bool rst;
    bool syn;
    bool fin;

    inline bool all_zero() {
        if ((ecn == false) &&
            (cwr == false) &&
            (ecn_echo == false) &&
            (urg == false) &&
            (ack == false) &&
            (psh == false) &&
            (rst == false) &&
            (syn == false) &&
            (fin == false)) {
            return true;
        }

        return false;
    }

    inline bool is_syn()
    { return syn == true; }

    inline bool is_syn_ack()
    { return (syn == true) && (ack == true); }

    inline bool is_fin()
    { return fin == true; }

    inline bool is_fin_ack()
    { return (fin == true) && (ack == true); }

    inline bool is_rst()
    { return rst == true; }
};

struct tcp_options_mss {
    uint8_t len;
    uint16_t mss;
};

struct tcp_options {
    tcp_options_mss mss;
};

struct tcp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_no;
    uint32_t ack_no;
    uint8_t hdr_len;
    tcp_flags flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
    bool contains_options;
    tcp_options opt;

    event_type deserialize(packet_buf &buf,
                           const std::shared_ptr<nos::core::logging> &log);
    inline bool has_options()
    { return contains_options == true; }
    void free_hdr() { }
};

}

#endif
