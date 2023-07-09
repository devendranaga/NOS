/**
 * @brief - Implements Firewall Rules.
 *
 * @author - Devendra Naga.
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __NOS_FIREWALL_RULES_H__
#define __NOS_FIREWALL_RULES_H__

#include <cstdint>
#include <string>
#include <cstring>
#include <vector>
#include <nos_core.h>

namespace nos::firewall
{

/*
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
#define FW_RULE_PROTOCOL_TCP 6
#define FW_RULE_PROTOCOL_UDP 17

struct rule_config_mac_rules {
    uint8_t from_src_mac[6];
    uint8_t to_dst_mac[6];
    uint16_t ethertype;
};

struct rule_config_ipv4_rules {
    uint32_t from_src_ipv4;
    uint32_t to_dst_ipv4;
    uint32_t protocol;
};

/**
 * @brief - rule configuration.
 */
struct rule_config {
    std::string rule_name;
    uint32_t rule_id;
    bool mac_rule_available;
    bool ipv4_rule_available;
    rule_config_mac_rules mac_rule;
    rule_config_ipv4_rules ipv4_rule;

    explicit rule_config() {
        rule_name = "";
        rule_id = 0;
        mac_rule_available = false;
        ipv4_rule_available = false;
        std::memset(&mac_rule, 0, sizeof(mac_rule));
        std::memset(&ipv4_rule, 0, sizeof(ipv4_rule));
    }
    ~rule_config() { }
};

/**
 * @brief - Interface for Firewall rules.
 */
class firewall_rules {
    public:
        explicit firewall_rules();
        ~firewall_rules();

        /**
         * @brief - Parse the rules file.
         *
         * @param[in] rule_file: rules configuration.
         * @param[in] log: logging instance.
         *
         * @return 0 on success -1 on failure.
         */
        int parse(const std::string &rule_file,
                  const std::shared_ptr<nos::core::logging> &log);

        /**
         * @brief - get rules configuration.
         *
         * @return vector of rules read from the rules file.
         */
        const std::vector<rule_config> &get() { return ruleset_; }

        /**
         * @brief - print the rules.
         */
        void print();

    private:
        std::vector<rule_config> ruleset_;
};

}

#endif
