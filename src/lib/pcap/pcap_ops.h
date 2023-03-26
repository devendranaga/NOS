#ifndef __FW_PCAP_OPS_H__
#define __FW_PCAP_OPS_H__

/* packet header */
struct fw_pcaprec_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

typedef struct fw_pcaprec_hdr fw_pcaprec_hdr_t;

void *fw_pcap_ops_writer_init(const char *filename);
void fw_pcap_ops_writer_deinit(void *pcap_ctx);
int fw_pcap_ops_write_packet(void *pcap_ctx, uint8_t *pkt, uint32_t pkt_len);

void *fw_pcap_ops_pcap_reader_init(const char *filename);
void fw_pcap_ops_pcap_reader_deinit(void *pcap_ctx);
int fw_pcap_ops_read_packet(void *pcap_ctx, fw_pcaprec_hdr_t *rec_hdr,
                            uint8_t *buf, size_t buflen);

#endif

