/**
 * @brief - Implements packet generator.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com.
 * @copyright 2023-present All rights reserved.
 */
#include <packet_gen.h>

#define CMD_ARGS "-i:P:"

struct packet_gen_config {
    char ifname[20];
    bool pcap_replay;
    char pcap_filename[128];
};

typedef struct packet_gen_config packet_gen_config_t;

STATIC void usage(const char *progname)
{
    fprintf(stderr, "<%s>   <-i interface name>\n"
                    "\t\t <-P pcap filename>\n", progname);
}

STATIC int packet_gen_parse_cmd_args(int argc, char **argv,
                                     packet_gen_config_t *pkt_gen_config)
{
    int ret;

    while ((ret = getopt(argc, argv, CMD_ARGS)) != -1) {
        switch (ret) {
            case 'i':
                strcpy(pkt_gen_config->ifname, optarg);
            break;
            case 'P':
                pkt_gen_config->pcap_replay = true;
                strcpy(pkt_gen_config->pcap_filename, optarg);
            break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    packet_gen_config_t pkt_gen_config;
    int ret;

    /* Read command line arguments. */
    memset(&pkt_gen_config, 0, sizeof(packet_gen_config_t));
    ret = packet_gen_parse_cmd_args(argc, argv, &pkt_gen_config);
    if (ret < 0) {
        return -1;
    }

    /* Run pcap replay. */
    if (pkt_gen_config.pcap_replay) {
        packet_gen_pcap_replay_run(pkt_gen_config.ifname,
                                   pkt_gen_config.pcap_filename,
                                   100);
    }

    return 0;
}

