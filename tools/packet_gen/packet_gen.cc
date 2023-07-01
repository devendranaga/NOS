#include <iostream>
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
                    "\t <-r replay interval in ms>\n",
                    progname);
}

packet_gen::packet_gen(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "i:p:r:")) != -1) {
        switch (ret) {
            case 'i':
                interface_name_ = std::string(optarg);
            break;
            case 'p':
                pcap_replay_ = true;
                pcap_replay_file_ = std::string(optarg);
            break;
            case 'r':
                ret = nos::core::convert_to_uint(optarg, &replay_intvl_ms_);
                if (ret != 0) {
                    usage(argv[0]);
                    throw std::runtime_error("invalid value for replay interval");
                }
            default:
                usage(argv[0]);
                throw std::runtime_error("incorrect command line args");
        }
    }

    raw_ = std::make_shared<nos::core::raw_socket>(interface_name_, 0);
    evt_mgr_ = nos::core::evt_mgr_intf::instance();
    auto callback = std::bind(&packet_gen::pcap_replay_callback_fn, this);
    evt_mgr_->register_timer(0, replay_intvl_ms_, callback, false);
}

void packet_gen::pcap_replay_callback_fn()
{

}

packet_gen::~packet_gen()
{

}

void packet_gen::run()
{
    evt_mgr_->run();
}

}

int main(int argc, char **argv)
{
    nos::packet_gen::packet_gen pkt_gen(argc, argv);

    pkt_gen.run();
}
