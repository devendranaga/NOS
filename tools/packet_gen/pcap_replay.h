/**
 * @brief - Defines pcap replay.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FW_PACKET_GEN_PCAP_REPLAY_H__
#define __FW_PACKET_GEN_PCAP_REPLAY_H__

#include <stdint.h>
#include <unistd.h>
#include <pcap_ops.h>
#include <linux_raw.h>

int packet_gen_pcap_replay_run(const char *, const char *, uint32_t);

#endif

