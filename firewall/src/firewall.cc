#include <getopt.h>
#include <fstream>
#include <packet.h>
#include <firewall.h>

namespace nos::firewall {

int firewall_config::parse(const std::string &conf,
                           std::shared_ptr<nos::core::logging> &log)
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

    auto evt_fmt = events["event_format"].asString();

    if (evt_fmt == "light") {
        evt_conf_.evt_fmt = event_format::Light;
    } else if (evt_fmt == "full") {
        evt_conf_.evt_fmt = event_format::Full;
    } else {
        log->err("firewall: invalid event_format %s\n", evt_fmt);
        return -1;
    }

    auto evt_msg_fmt = events["event_msg_format"].asString();

    if (evt_msg_fmt == "v1") {
        evt_conf_.evt_msg_fmt = event_msg_format::v1;
    } else {
        log->err("firewall: invalid msg format %s\n", evt_msg_fmt);
        return -1;
    }

    evt_conf_.evt_upload_cfg.binary_cfg.enable =
                events["event_uploads"]["binary"]["enable"].asInt();
    auto evt_proto = events["event_uploads"]["binary"]["protocol"].asString();

    if (evt_proto == "tcp") {
        evt_conf_.evt_upload_cfg.binary_cfg.protocol =
                event_protocol::tcp;
    } else {
        log->err("firewall: invalid event_upload binary protocol %s\n", evt_proto);
        return -1;
    }

    evt_conf_.evt_upload_cfg.binary_cfg.server_ip =
                events["event_uploads"]["binary"]["server_ip"].asString();

    evt_conf_.evt_upload_cfg.binary_cfg.server_port =
                events["event_uploads"]["binary"]["server_port"].asInt();


    evt_conf_.evt_upload_cfg.protobuf_cfg.enable =
                events["event_uploads"]["protobuf"]["enable"].asInt();
    evt_proto = events["event_uploads"]["protobuf"]["protocol"].asString();
    if (evt_proto == "tcp") {
        evt_conf_.evt_upload_cfg.protobuf_cfg.protocol =
                event_protocol::tcp;
    } else {
        log->err("firewall: invalid evt_upload protobuf protocol %s\n", evt_proto);
        return -1;
    }

    evt_conf_.evt_upload_cfg.protobuf_cfg.server_ip =
                events["event_uploads"]["protobuf"]["server_ip"].asString();

    evt_conf_.evt_upload_cfg.protobuf_cfg.server_port =
                events["event_uploads"]["protobuf"]["server_port"].asInt();


    evt_conf_.evt_upload_cfg.mqtt_cfg.enable =
                events["event_uploads"]["mqtt"]["enable"].asInt();
    evt_proto = events["event_uploads"]["protobuf"]["protocol"].asString();
    if (evt_proto == "tcp") {
        evt_conf_.evt_upload_cfg.mqtt_cfg.protocol =
                event_protocol::tcp;
    } else {
        log->err("firewall: invalid event_uploads config protocol %s\n", evt_proto);
        return -1;
    }
    evt_conf_.evt_upload_cfg.mqtt_cfg.server_ip =
                events["event_uploads"]["mqtt"]["server_ip"].asString();
    evt_conf_.evt_upload_cfg.mqtt_cfg.server_port =
                events["event_uploads"]["mqtt"]["server_port"].asInt();
    evt_conf_.evt_upload_cfg.mqtt_cfg.event_topic =
                events["event_uploads"]["mqtt"]["event_topic"].asString();

    return 0;
}

void firewall_intf::receive_callback()
{
    packet_buf pkt_buf(ifname_);
    uint8_t mac[6];
    int ret;

    ret = raw_->recv_msg(mac, pkt_buf.data, sizeof(pkt_buf.data));
    if (ret < 0) {
        return;
    }

    pkt_buf.data_len = ret;
    {
        std::unique_lock<std::mutex> lock(pkt_queue_lock_);
        pkt_queue_.emplace(pkt_buf);
    }
}

void firewall_intf::filter_callback()
{

}

int firewall_intf::create_raw(const std::string &ifname)
{
    int ret;

    ifname_ = ifname;

    raw_ = std::make_unique<nos::core::raw_socket>(ifname, 0x0);

    rx_thr_ = std::make_unique<std::thread>(&firewall_intf::receive_callback, this);
    rx_thr_->detach();

    parser_thr_ = std::make_unique<std::thread>(&firewall_intf::parser_callback, this);
    parser_thr_->detach();

    filter_thr_ = std::make_unique<std::thread>(&firewall_intf::filter_callback, this);
    filter_thr_->detach();

    /* Initialize the event manager interface. */
    ret = firewall_event_mgr::instance()->init();
    if (ret < 0) {
        return -1;
    }

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
    firewall_config *conf;
    firewall_rules rules;
    int ret;

    log_ = NOS_LOG_INTF_CONSOLE();

    ret = firewall_config::instance()->parse(conf_file, log_);
    if (ret < 0) {
        return -1;
    }

    log_->info("firewall: parsing rules file ok\n");

    evt_mgr_ = nos::core::evt_mgr_intf::instance();

    conf = firewall_config::instance();

    ret = rules.parse(FIREWALL_RULES_FILE, log_);
    if (ret < 0) {
        log_->err("firewall: failed to parse rules file [%s]\n",
                                           FIREWALL_RULES_FILE);
        return ret;
    }

    for (auto it : conf->intf_list_) {
        std::shared_ptr<firewall_intf> intf;

        intf = std::make_shared<firewall_intf>(log_);
        ret = intf->create_raw(it.ifname);
        if (ret < 0) {
            log_->err("firewall: failed to init socket on [%s]\n",
                                    it.ifname.c_str());
            return -1;
        }
        intf_list_.emplace_back(intf);
    }

    return 0;
}

void firewall_ctx::run()
{
    evt_mgr_->run();
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
