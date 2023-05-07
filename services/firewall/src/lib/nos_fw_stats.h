#ifndef __NOS_FW_STATS_H__
#define __NOS_FW_STATS_H__

typedef struct nos_fw_icmp_stats {
    uint64_t n_rx;
    uint64_t n_dropped;
} nos_fw_icmp_stats_t;

typedef struct nos_fw_arp_stats {
    uint64_t n_rx;
    uint64_t n_dropped;
} nos_fw_arp_stats_t;

typedef struct nos_fw_stats_intf {
    char ifname[24];
    uint64_t n_rx;
    uint64_t n_dropped;

    nos_fw_arp_stats_t arp_stats;
    nos_fw_icmp_stats_t icmp_stats;
    struct nos_fw_stats_intf *next;
} nos_fw_stats_intf_t;

#endif

