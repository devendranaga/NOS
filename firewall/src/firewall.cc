#include <getopt.h>
#include <fstream>
#include <firewall.h>

namespace nos::firewall {

int firewall_config::parse(const std::string &conf)
{
    Json::Value root;
    std::ifstream config(conf, std::ifstream::binary);

    config >> root;

    auto intf_list = root["intf_list"];

    for (auto it : intf_list) {
        firewall_intf_config intf_conf;

        intf_conf.ifname = it["interface_name"].asString();
        intf_conf.rules_file = it["rules_file"].asString();

        intf_list_.emplace_back(intf_conf);
    }

    auto events = root["events"];

    for (auto it : events) {
        auto evt_fmt = it["event_format"].asString();

        if (evt_fmt == "light") {
            evt_conf_.evt_fmt = event_format::Light;
        } else if (evt_fmt == "full") {
            evt_conf_.evt_fmt = event_format::Full;
        } else {
            return -1;
        }

        auto evt_msg_fmt = it["event_msg_format"].asString();

        if (evt_msg_fmt == "v1") {
            evt_conf_.evt_msg_fmt = event_msg_format::v1;
        } else {
            return -1;
        }


        evt_conf_.evt_upload_cfg.binary_cfg.enable =
                it["event_uploads"]["binary"]["enable"].asInt();
        auto evt_proto = it["event_uploads"]["binary"]["protocol"].asString();

        if (evt_proto == "tcp") {
            evt_conf_.evt_upload_cfg.binary_cfg.protocol =
                event_protocol::tcp;
        } else {
            return -1;
        }

        evt_conf_.evt_upload_cfg.binary_cfg.server_ip =
                it["event_uploads"]["binary"]["server_ip"].asString();

        evt_conf_.evt_upload_cfg.binary_cfg.server_port =
                it["event_uploads"]["binary"]["server_port"].asInt();


        evt_conf_.evt_upload_cfg.protobuf_cfg.enable =
                it["event_uploads"]["protobuf"]["enable"].asInt();
        evt_proto = it["event_uploads"]["protobuf"]["protocol"].asString();
        if (evt_proto == "tcp") {
            evt_conf_.evt_upload_cfg.protobuf_cfg.protocol =
                event_protocol::tcp;
        } else {
            return -1;
        }

        evt_conf_.evt_upload_cfg.protobuf_cfg.server_ip =
                it["event_uploads"]["protobuf"]["server_ip"].asString();

        evt_conf_.evt_upload_cfg.protobuf_cfg.server_port =
                it["event_uploads"]["protobuf"]["server_port"].asInt();


        evt_conf_.evt_upload_cfg.mqtt_cfg.enable =
                it["event_uploads"]["mqtt"]["enable"].asInt();
        evt_proto = it["event_uploads"]["protobuf"]["protocol"].asString();
        if (evt_proto == "tcp") {
            evt_conf_.evt_upload_cfg.mqtt_cfg.protocol =
                event_protocol::tcp;
        } else {
            return -1;
        }
        evt_conf_.evt_upload_cfg.mqtt_cfg.server_ip =
                it["event_uploads"]["mqtt"]["server_ip"].asString();
        evt_conf_.evt_upload_cfg.mqtt_cfg.server_port =
                it["event_uploads"]["mqtt"]["server_port"].asInt();
        evt_conf_.evt_upload_cfg.mqtt_cfg.event_topic =
                it["event_uploads"]["mqtt"]["event_topic"].asString();
    }

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
