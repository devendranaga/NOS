#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <nos_core.h>
#include <x509_parser.h>

#define NOS_CERT_BUF_LEN_MAX 8192 * 2

static int x509_der_file_to_buf(const char *filename,
                                uint8_t *buffer,
                                uint32_t buffer_size)
{
    int ret = -1;
    int fd;

    fd = nos_fileio_open(filename, "rb");
    if (fd < 0) {
        return -1;
    }

    ret = nos_fileio_read(fd, (char *)buffer, buffer_size);

    nos_fileio_close(fd);

    return ret;
}

#define ASN1_SEQUENCE_TAG               0x30
#define ASN1_SET_OF_TAG                 0x31

#define ASN1_BIT_STRING_TAG             0x03
#define ASN1_BOOLEAN_TAG                0x01
#define ASN1_INTEGER_TAG                0x02
#define ASN1_NULL_TAG                   0x05
#define ASN1_OBJECT_IDENTIFIER_TAG      0x06
#define ASN1_OCTET_STRING_TAG           0x04
#define ASN1_BMP_STRING_TAG             0x1E
#define ASN1_IA5_STRING_TAG             0x16
#define ASN1_PRINTABLE_STRING_TAG       0x13
#define ASN1_TELETEX_STRING_TAG         0x14
#define ASN1_UTF8_STRING_TAG            0x0C
#define ASN1_X509_VERSION_TAG           0xA0
#define ASN1_X509_VERSION_TAG_LEN       0x03

static int x509_asn1_parse_integer_u32(uint8_t *buffer,
                                       uint32_t *off,
                                       uint32_t *val,
                                       uint32_t buffer_size)
{
    int ret = -1;
    int len = 0;

    (*off) ++;

    len = buffer[*off];
    (*off) ++;

    if (len == 1) {
        *val = buffer[*off];
        (*off) ++;
        ret = 0;
    }

    return ret;
}

static int x509_asn1_parser_get_length(uint8_t *buffer,
                                       uint32_t *off, uint32_t buffer_size)
{
    int len_bytes = 0;
    int len = 0;

    if (buffer[*off] & 0x80) {
        len_bytes = buffer[*off] ^ 0x80;
        (*off) ++;
    }
    if (len_bytes != 0) {
        len = (buffer[*off] << 8) | (buffer[*off + 1]);
        (*off) += 2;
    }

    return len;
}

static int x509_parse_tbs_certificate_version(uint8_t *buffer,
                                              uint32_t *off,
                                              uint32_t buffer_size,
                                              nos_x509_certificate_t *cert)
{
    return x509_asn1_parse_integer_u32(buffer, off,
                                       &cert->certificate.version,
                                       buffer_size);
}

static int x509_parse_tbs_certificate_serial(uint8_t *buffer,
                                             uint32_t *off,
                                             uint32_t buffer_size,
                                             nos_x509_certificate_t *cert)
{
    uint32_t len = 0;

    (*off) ++;

    len = buffer[*off];
    (*off) ++;

    cert->certificate.serial_no_len = len;
    memcpy(cert->certificate.serial_no, &buffer[*off], len);
    (*off) += len;

    return 0;
}

static int x509_parse_asn1_object_identifier(uint8_t *buffer,
                                             uint32_t *off,
                                             uint32_t buffer_size,
                                             nos_x509_certificate_t *cert)
{
    uint32_t len = 0;

    (*off) ++;

    len = buffer[*off];
    (*off) ++;

    cert->certificate.signature_algid.obj_id_len = len;
    memcpy(cert->certificate.signature_algid.obj_id, &buffer[*off], len);
    (*off) += len;

    return 0;
}

static int x509_parse_tbs_algorithm_identifier(uint8_t *buffer,
                                               uint32_t *off,
                                               uint32_t buffer_size,
                                               nos_x509_certificate_t *cert)
{
    uint32_t len = 0;
    int ret;

    (*off) ++;
    len = buffer[*off];
    (void)len;
    (*off) ++;

    /*TODO: We do not know yet how to parse this. */
    if (buffer[*off] == ASN1_OBJECT_IDENTIFIER_TAG) {
        ret = x509_parse_asn1_object_identifier(buffer, off, buffer_size, cert);
        if (ret < 0) {
            return -1;
        }
    }
    if (buffer[*off] == ASN1_NULL_TAG) {
        /* Skip the 0x05 and 0x00. */
        (*off) += 2;
    }

    return 0;
}

static int x509_parse_tbs_certificate_issuer(uint8_t *buffer,
                                             uint32_t *off,
                                             uint32_t buffer_size,
                                             nos_x509_certificate_t *cert)
{
    (*off) ++;

    return 0;
}

static int x509_parse_tbs_certificate(uint8_t *buffer,
                                      uint32_t *off,
                                      uint32_t buffer_size,
                                      nos_x509_certificate_t *cert)
{
    int tbs_cert_len = 0;
    int ret = -1;

    if (buffer[*off] == ASN1_SEQUENCE_TAG) {
        (*off) ++;

        tbs_cert_len = x509_asn1_parser_get_length(buffer, off, buffer_size);
        if (tbs_cert_len > 0) {
            /* Parse version. */

            /* Always a version tag First. */
            if ((buffer[*off] == ASN1_X509_VERSION_TAG) &&
                (buffer[*off + 1] == ASN1_X509_VERSION_TAG_LEN) &&
                (buffer[*off + 2] == ASN1_INTEGER_TAG)) {
                (*off) += 2;

                ret = x509_parse_tbs_certificate_version(buffer, off, buffer_size, cert);
                if (ret < 0) {
                    return -1;
                }
            } else {
                return -1;
            }

            /* Parse serial number. */
            if ((buffer[*off]) == ASN1_INTEGER_TAG) {
                ret = x509_parse_tbs_certificate_serial(buffer, off, buffer_size, cert);
                if (ret < 0) {
                    return -1;
                }
            } else {
                return -1;
            }

            /* Parse Algorithm Identifier. */
            if (buffer[*off] == ASN1_SEQUENCE_TAG) {
                ret = x509_parse_tbs_algorithm_identifier(buffer, off, buffer_size, cert);
                if (ret < 0) {
                    return -1;
                }
            } else {
                return -1;
            }

            if (buffer[*off] == ASN1_SEQUENCE_TAG) {
                ret = x509_parse_tbs_certificate_issuer(buffer, off, buffer_size, cert);
            } else {
                return -1;
            }
        }
    }

    return ret;
}

static int x509_parse_certificate(uint8_t *buffer,
                                  uint32_t buffer_size,
                                  nos_x509_certificate_t *cert)
{
    int cert_len = 0;
    uint32_t off = 0;
    int ret = -1;

    if (buffer[off] == ASN1_SEQUENCE_TAG) {
        off ++;
        /* Skip header and start parsing certificate. */
        cert_len = x509_asn1_parser_get_length(buffer, &off, buffer_size);
        if (cert_len > 0) {
            ret = x509_parse_tbs_certificate(buffer, &off, buffer_size, cert);
        }
    }

    return ret;
}

static int x509_parse_buffer(uint8_t *buffer,
                             uint32_t buffer_size,
                             nos_x509_certificate_t *cert)
{
    nos_hexdump_network("x509", buffer, buffer_size);
    x509_parse_certificate(buffer, buffer_size, cert);

    return 0;
}

void x509_print(nos_x509_certificate_t *cert)
{
    int i;

    fprintf(stderr, "X509: {\n");

    fprintf(stderr, "\t tbsCertificate: {\n");

    fprintf(stderr, "\t\t version: %u\n", cert->certificate.version);

    fprintf(stderr, "\t\t serial: [");
    for (i = 0; i < cert->certificate.serial_no_len; i ++) {
        fprintf(stderr, "%02x ", cert->certificate.serial_no[i]);
    }
    fprintf(stderr, "]\n");

    fprintf(stderr, "\t\t Algorithm Identifier: {\n");

    fprintf(stderr, "\t\t\t oid: [");
    for (i = 0; i < cert->certificate.signature_algid.obj_id_len; i ++) {
        fprintf(stderr, "%02x ", cert->certificate.signature_algid.obj_id[i]);
    }

    fprintf(stderr, "]\n");

    fprintf(stderr, "\t\t }\n");

    fprintf(stderr, "\t }\n");

    fprintf(stderr, "}\n");
}

int x509_parse_der(const char *filename, nos_x509_certificate_t *cert)
{
    uint8_t *cert_buf;
    int ret = -1;

    cert_buf = calloc(1, NOS_CERT_BUF_LEN_MAX);
    if (!cert_buf) {
        return -1;
    }

    ret = x509_der_file_to_buf(filename, cert_buf, NOS_CERT_BUF_LEN_MAX);
    if (ret > 0) {
        ret = x509_parse_buffer(cert_buf, ret, cert);
    }

    if (cert_buf) {
        free(cert_buf);
    }

    return ret;
}

void x509_free_der(nos_x509_certificate_t *cert)
{
}

