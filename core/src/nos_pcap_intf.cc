/**
 *
 * @brief - pcap reader and writer interface
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com)
*/
#include <iostream>
#include <cstring>
#include <time.h>
#include <sys/time.h>
#include <nos_pcap_intf.h>

namespace nos::core
{

nos_pcap_writer::nos_pcap_writer(std::string filename)
{
    pcap_hdr_t glob_hdr;

    glob_hdr = format_default_glob_header();

    fp = fopen(filename.c_str(), "w");
    if (!fp) {
        throw std::runtime_error("failed to open pcap file for writing ");
    }

    fwrite(&glob_hdr, sizeof(glob_hdr), 1, fp);
}

nos_pcap_writer::~nos_pcap_writer()
{
    if (fp != nullptr) {
        fclose(fp);
    }
}

pcaprec_hdr_t nos_pcap_writer::format_pcap_pkthdr(size_t pktsize)
{
    pcaprec_hdr_t rec_hdr;
    struct timeval tv;

    std::memset(&rec_hdr, 0, sizeof(rec_hdr));
    gettimeofday(&tv, 0);

    rec_hdr.ts_sec = tv.tv_sec;
    rec_hdr.ts_usec = tv.tv_usec;
    rec_hdr.incl_len = pktsize;
    rec_hdr.orig_len = pktsize;

    return rec_hdr;
}

int nos_pcap_writer::write_packet(pcaprec_hdr_t *rec, uint8_t *buf)
{
    int ret;

    ret = fwrite(rec, sizeof(*rec), 1, fp);
    if (ret != 1) {
        return -1;
    }

    ret = fwrite(buf, rec->incl_len, 1, fp);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

pcap_hdr_t nos_pcap_writer::format_default_glob_header()
{
    pcap_hdr_t glob_hdr;

    std::memset(&glob_hdr, 0, sizeof(glob_hdr));
    glob_hdr.magic_number = 0xa1b2c3d4;
    glob_hdr.version_major = 2;
    glob_hdr.version_minor = 4;
    glob_hdr.thiszone = 0;
    glob_hdr.sigfigs = 0;
    glob_hdr.snaplen = 65535;
    glob_hdr.network = 1;

    return glob_hdr;
}

nos_pcap_reader::nos_pcap_reader(std::string filename)
{
    int ret;

    fp = fopen(filename.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("failed to open file for reading");
        return;
    }

    ret = fread(&glob_hdr, sizeof(glob_hdr), 1, fp);
    if (ret != 1) {
        throw std::runtime_error("failed to read pcap global header");
    }

    /* Magic number. */
    if (glob_hdr.magic_number != 0xa1b2c3d4) {
        throw std::runtime_error("invalid pcap magic");
    }
}

nos_pcap_reader::~nos_pcap_reader()
{
    if (fp != nullptr) {
        fclose(fp);
    }
}

int nos_pcap_reader::read_packet(pcaprec_hdr_t *rec_hdr, uint8_t *buf, size_t buflen)
{
    int ret;

    ret = fread(rec_hdr, sizeof(*rec_hdr), 1, fp);
    if (ret != 1) {
        return -1;
    }

    ret = fread(buf, rec_hdr->incl_len, 1, fp);
    if (ret != 1) {
        return -1;
    }

    if (feof(fp)) {
        return -1;
    }

    count ++;

    return rec_hdr->incl_len;
}

}
