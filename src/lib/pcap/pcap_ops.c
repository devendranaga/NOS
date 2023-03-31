#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <firewall_common.h>
#include <pcap_ops.h>

/* global header */
struct pcap_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
};

typedef struct pcap_hdr pcap_hdr_t;

struct fw_pcap_ops_context {
    FILE *fp;
};

STATIC pcap_hdr_t format_default_glob_header()
{
    pcap_hdr_t glob_hdr;

    memset(&glob_hdr, 0, sizeof(glob_hdr));
    glob_hdr.magic_number = 0xa1b2c3d4;
    glob_hdr.version_major = 2;
    glob_hdr.version_minor = 4;
    glob_hdr.thiszone = 0;
    glob_hdr.sigfigs = 0;
    glob_hdr.snaplen = 65535;
    glob_hdr.network = 1;

    return glob_hdr;
}

void *fw_pcap_ops_writer_init(const char *filename)
{
    struct fw_pcap_ops_context *ops;
    pcap_hdr_t glob_hdr;

    ops = calloc(1, sizeof(struct fw_pcap_ops_context));
    if (!ops) {
        return NULL;
    }

    glob_hdr = format_default_glob_header();

    ops->fp = fopen(filename, "w");
    if (!ops->fp) {
        free(ops);
        return NULL;
    }

    fwrite(&glob_hdr, sizeof(glob_hdr), 1, ops->fp);

    return ops;
}

void fw_pcap_ops_writer_deinit(void *pcap_ctx)
{
    struct fw_pcap_ops_context *ops = pcap_ctx;

    if (ops->fp != NULL) {
        fflush(ops->fp);
        fclose(ops->fp);
    }
}

STATIC fw_pcaprec_hdr_t fw_pcap_ops_format_pcap_pkthdr(uint32_t pktsize)
{
    fw_pcaprec_hdr_t rec_hdr;
    struct timeval tv;

    memset(&rec_hdr, 0, sizeof(rec_hdr));
    gettimeofday(&tv, 0);

    rec_hdr.ts_sec = tv.tv_sec;
    rec_hdr.ts_usec = tv.tv_usec;
    rec_hdr.incl_len = pktsize;
    rec_hdr.orig_len = pktsize;

    return rec_hdr;
}

int fw_pcap_ops_write_packet(void *pcap_ctx, uint8_t *pkt, uint32_t pkt_len)
{
    struct fw_pcap_ops_context *ops = pcap_ctx;
    fw_pcaprec_hdr_t rec;
    int ret;

    memset(&rec, 0, sizeof(rec));
    rec = fw_pcap_ops_format_pcap_pkthdr(pkt_len);
    ret = fwrite(&rec, sizeof(rec), 1, ops->fp);
    if (ret != 1) {
        return -1;
    }

    ret = fwrite(pkt, rec.incl_len, 1, ops->fp);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

void *fw_pcap_ops_pcap_reader_init(const char *filename)
{
    struct fw_pcap_ops_context *ops;
    pcap_hdr_t glob_hdr;
    int ret;

    ops = calloc(1, sizeof(struct fw_pcap_ops_context));
    if (!ops) {
        return NULL;
    }

    ops->fp = fopen(filename, "r");
    if (!ops->fp) {
        printf("failed to open %s\n", filename);
        free(ops);
        return NULL;
    }

    ret = fread(&glob_hdr, sizeof(glob_hdr), 1, ops->fp);
    if (ret != 1) {
        fclose(ops->fp);
        free(ops);
        return NULL;
    }

    return ops;
}

void fw_pcap_ops_pcap_reader_deinit(void *pcap_ctx)
{
    struct fw_pcap_ops_context *ops = pcap_ctx;

    if (ops->fp != NULL) {
        fclose(ops->fp);
    }
}

int fw_pcap_ops_read_packet(void *pcap_ctx, fw_pcaprec_hdr_t *rec_hdr,
                            uint8_t *buf, uint32_t buflen)
{
    struct fw_pcap_ops_context *ops = pcap_ctx;
    int ret;

    ret = fread(rec_hdr, sizeof(*rec_hdr), 1, ops->fp);
    if (ret != 1) {
        return -1;
    }

    ret = fread(buf, rec_hdr->incl_len, 1, ops->fp);
    if (ret != 1) {
        return -1;
    }

    return 0;
}


