/**
 * @brief - Implements pcap replay.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <stdio.h>
#include <pcap_replay.h>

int packet_gen_pcap_replay_run(const char *device, const char *filename,
                               uint32_t delay_ms)
{
    fw_pcaprec_hdr_t pcap_hdr;
    uint8_t pkt[4096];
    void *raw_drv;
    void *pcap_r;
    int ret;

    /* Create Raw driver. */
    raw_drv = linux_raw_init(device);
    if (!raw_drv) {
        return -1;
    }

    /* Create pcap Reader. */
    pcap_r = fw_pcap_ops_pcap_reader_init(filename);
    if (!pcap_r) {
        return -1;
    }

    while (1) {
        /* Read each packet and send it over the raw interface. */
        ret = fw_pcap_ops_read_packet(pcap_r, &pcap_hdr, pkt, sizeof(pkt));
        if (ret < 0) {
            break;
        }
        linux_raw_write(raw_drv, pkt, pcap_hdr.orig_len);
        usleep(delay_ms * 1000U);
    }

    fw_pcap_ops_pcap_reader_deinit(pcap_r);
    linux_raw_deinit(raw_drv);

    return 0;
}

