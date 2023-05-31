#include <getopt.h>
#include <fstream>
#include <firewall.h>

namespace nos::firewall {

int firewall_config::parse(const std::string &conf)
{
    Json::Value root;
    std::ifstream config(conf, std::ifstream::binary);

    config >> root;

    return 0;
}

void firewall_intf::receive_callback()
{

}

int firewall_intf::create_raw(const std::string &ifname)
{
    raw_ = std::make_unique<nos::core::raw_socket>(ifname, 0x0);

    rx_thr_ = std::make_unique<std::thread>(&firewall_intf::receive_callback, this);
    rx_thr_->detach();

    return 0;
}

firewall_ctx::firewall_ctx()
{

}

firewall_ctx::~firewall_ctx()
{

}

int firewall_ctx::init(const std::string &conf_file)
{
    int ret;

    ret = firewall_config::instance()->parse(conf_file);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

void firewall_ctx::run()
{

}

}

static void usage(const char *progname)
{
    fprintf(stderr, "<%s> <-f config file>\n", progname);
}

int main(int argc, char **argv)
{
    nos::firewall::firewall_ctx fw_ctx;
    std::string conf_file;
    int ret;

    while ((ret = getopt(argc, argv, "f:")) != -1) {
        switch (ret) {
            case 'f':
                conf_file = optarg;
            break;
            default:
                usage(argv[0]);
            break;
        }
    }

    ret = fw_ctx.init(conf_file);
    if (ret < 0) {
        return -1;
    }

    fw_ctx.run();

    return 0;
}
