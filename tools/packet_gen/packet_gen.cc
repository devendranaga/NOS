/**
 * @brief - Implements packet generator.
 * 
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
*/
#include <iostream>
#include <cstring>
#include <memory>
#include <getopt.h>
#include <packet_gen.h>

namespace nos::packet_gen
{

static void usage(const char *progname)
{
    fprintf(stderr, "<%s> [i:p:r:]\n"
                    "\t <-i interface name> \n"
                    "\t <-p pcap filename> \n"
                    "\t <-t replay interval in ms>\n"
                    "\t <-r repeat replay>\n",
                    progname);
}

packet_gen::packet_gen(int argc, char **argv) :
                            pcap_replay_(false),
                            replay_intvl_ms_(100),
                            repeat_(false)
{
    int ret;

    while ((ret = getopt(argc, argv, "i:p:t:r")) != -1) {
        switch (ret) {
            case 'i':
                interface_name_ = std::string(optarg);
            break;
            case 'p':
                pcap_replay_ = true;
                pcap_replay_file_ = std::string(optarg);
            break;
            case 'r':
                repeat_ = true;
            break;
            case 't':
                ret = nos::core::convert_to_uint(optarg, &replay_intvl_ms_);
                if (ret != 0) {
                    usage(argv[0]);
                    throw std::runtime_error("invalid value for replay interval");
                }
            break;
            default:
                usage(argv[0]);
                throw std::runtime_error("incorrect command line args");
        }
    }

    raw_ = std::make_shared<nos::core::raw_socket>(interface_name_, 0);
    evt_mgr_ = nos::core::evt_mgr_intf::instance();
}

int packet_gen::pcap_replay_fn()
{
    nos::core::nos_pcap_reader rd(pcap_replay_file_);
    uint8_t dummy_mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0xEF};
    int ret;

    while (1) {
        nos::core::pcaprec_hdr_t hdr;
        uint8_t pkt[2400];

        std::this_thread::sleep_for(std::chrono::milliseconds(replay_intvl_ms_));

        std::memset(pkt, 0, sizeof(pkt));
        std::memset(&hdr, 0, sizeof(hdr));
        ret = rd.read_packet(&hdr, pkt, sizeof(pkt));
        if (ret < 0) {
            return -1;
        }

        raw_->send_msg(dummy_mac, pkt, hdr.incl_len);
    }

    return 0;
}

packet_gen::~packet_gen()
{

}

void packet_gen::run()
{
    int ret;

    if (pcap_replay_) {
        do {
            ret = pcap_replay_fn();
        } while (repeat_);
    } else {
        evt_mgr_->run();
    }
}

}

int main(int argc, char **argv)
{
    nos::packet_gen::packet_gen pkt_gen(argc, argv);

    pkt_gen.run();
}
