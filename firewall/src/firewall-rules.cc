#include <fstream>
#include <jsoncpp/json/json.h>
#include <firewall-rules.h>
#include <nos_core.h>

namespace nos::firewall
{

firewall_rules::firewall_rules() { }
firewall_rules::~firewall_rules() { }

static int parse_rule_name(Json::Value &val, rule_config &conf)
{
    conf.rule_name = val.asString();

    return 0;
}

static int parse_rule_id(Json::Value &val, rule_config &conf)
{
    conf.rule_id = val.asUInt();

    return 0;
}

static int parse_ethertype(Json::Value &val, rule_config &conf)
{
    int ret = 0;

    if (val.asString().length() != 0) {
        ret = nos::core::convert_to_hex(val.asString(),
                                        (uint32_t *)&conf.mac_rule.ethertype);
        if (ret == 0) {
            conf.mac_rule_available = true;
        } else {
            ret = -1;
        }
    }

    return ret;
}

static int parse_from_src_mac(Json::Value &val, rule_config &conf)
{
    int ret = 0;

    if (val.asString().length() != 0) {
        ret = nos::core::convert_mac(val.asString(), conf.mac_rule.from_src_mac);
        if (ret == 0) {
            conf.mac_rule_available = true;
        } else {
            ret = -1;
        }
    }
    return ret;
}

static int parse_to_dst_mac(Json::Value &val, rule_config &conf)
{
    int ret = 0;

    if (val.asString().length() != 0) {
        ret = nos::core::convert_mac(val.asString(), conf.mac_rule.to_dst_mac);
        if (ret == 0) {
            conf.mac_rule_available = true;
        } else {
            ret = -1;
        }
    }
    return ret;
}

static int parse_src_ipv4(Json::Value &val, rule_config &conf)
{
    int ret = 0;

    if (val.asString().length() != 0) {
        ret = nos::core::convert_to_ipv4(val.asString().c_str(), &conf.ipv4_rule.from_src_ipv4);
        if (ret == 0) {
            conf.ipv4_rule_available = true;
        } else {
            ret = -1;
        }
    }
    return ret;
}

static int parse_dst_ipv4(Json::Value &val, rule_config &conf)
{
    int ret = 0;

    if (val.asString().length() != 0) {
        ret = nos::core::convert_to_ipv4(val.asString().c_str(), &conf.ipv4_rule.to_dst_ipv4);
        if (ret == 0) {
            conf.ipv4_rule_available = true;
        } else {
            ret = -1;
        }
    }
    return ret;
}

static int parse_protocol(Json::Value &val, rule_config &conf)
{
    int ret = 0;

    if (val.asString().length() != 0) {
        if (val.asString() == "tcp") {
            conf.ipv4_rule.protocol = FW_RULE_PROTOCOL_TCP;
            conf.ipv4_rule_available = true;
        } else {
            ret = -1;
        }
    }
    return ret;
}

struct rule_metadata {
    const char *rule_str;
    int (*parser_callback)(Json::Value &val, rule_config &conf);
} rule_metadata_list[] = {
    {"rule_name",       parse_rule_name},
    {"rule_id",         parse_rule_id},
    {"from_src_mac",    parse_from_src_mac},
    {"to_dst_mac",      parse_to_dst_mac},
    {"ethertype",       parse_ethertype},
    {"from_src_ipv4",   parse_src_ipv4},
    {"to_dst_ipv4",     parse_dst_ipv4},
    {"protocol",        parse_protocol},
};

void firewall_rules::print()
{
    for (auto it : ruleset_) {
        printf("rule: {\n");
        printf("\t rule_name: %s\n", it.rule_name.c_str());
        printf("\t rule_id : %u\n", it.rule_id);
        if (it.mac_rule_available) {
            printf("\t from_src: [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                                    it.mac_rule.from_src_mac[0],
                                    it.mac_rule.from_src_mac[1],
                                    it.mac_rule.from_src_mac[2],
                                    it.mac_rule.from_src_mac[3],
                                    it.mac_rule.from_src_mac[4],
                                    it.mac_rule.from_src_mac[5]);
            printf("\t ethertype 0x%04x\n", it.mac_rule.ethertype);
        }
        if (it.ipv4_rule_available) {
            printf("\t from_src_ipv4: %u\n", it.ipv4_rule.from_src_ipv4);
            printf("\t from_dst_ipv4: %u\n", it.ipv4_rule.to_dst_ipv4);
            printf("\t protocol: %d\n", it.ipv4_rule.protocol);
        }
        printf("}\n");
    }
}

int firewall_rules::parse(const std::string &rules_file,
                          const std::shared_ptr<nos::core::logging> &log)
{
    Json::Value root;
    std::ifstream conf(rules_file, std::ifstream::binary);
    int ret;

    conf >> root;

    auto rules_str = root["rules"];

    for (auto it : rules_str) {
        const Json::Value default_val = Json::Value("");
        rule_config config;

        for (uint32_t i = 0; i < sizeof(rule_metadata_list) /
                                 sizeof(rule_metadata_list[0]); i ++) {
            auto val = it.get(rule_metadata_list[i].rule_str, default_val);
            rule_metadata_list[i].parser_callback(val, config);
        }

        ruleset_.push_back(config);
    }

    print();
    return 0;
}

}
