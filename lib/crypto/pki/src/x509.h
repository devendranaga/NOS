#ifndef __NOS_X509_H__
#define __NOS_X509_H__

#include <stdint.h>

typedef enum nos_x509_algorithm_type {
    SHA256_WITH_RSA_2048,
} nos_x509_algorithm_type_t;

typedef struct nos_x509_tbs_sig_alg_id {
    nos_x509_algorithm_type_t           alg_type;
    uint8_t                             algorithm_parameters;
} nos_x509_tbs_sig_alg_id_t;

typedef struct nos_x509_issuer_name {
    char *country;
    char *org;
    char *org_unit;
    char *common_name;
} nos_x509_issuer_name_t;

typedef struct nos_x509_subject_name {
    char *country;
    char *org;
    char *org_unit;
    char *common_name;
} nos_x509_subject_name_t;

typedef struct nos_x509_timestamp {
    uint32_t year;
    uint32_t mon;
    uint32_t day;
    uint32_t hour;
    uint32_t min;
    uint32_t sec;
} nos_x509_timestamp_t;

typedef struct nos_x509_validity {
    nos_x509_timestamp_t                not_before;
    nos_x509_timestamp_t                not_after;
} nos_x509_validity_t;

typedef struct nos_x509_pubkey_rsa {
    uint32_t                            pubkey_len;
    uint8_t                             pubkey[1024];
} nos_x509_pubkey_rsa_t;

typedef struct nos_x509_subject_pubkey_info {
    nos_x509_algorithm_type_t           alg_type;
    uint8_t                             algorithm_parameters;
    nos_x509_pubkey_rsa_t               rsa_pubkey;
} nos_x509_subject_pubkey_info_t;

typedef struct nos_x509_tbs_certificate {
    uint32_t                            version;
    uint8_t                             serial_no[32];
    uint8_t                             serial_no_len;
    nos_x509_tbs_sig_alg_id_t           signature_algid;
    nos_x509_issuer_name_t              issuer_name;
    nos_x509_validity_t                 validity;
    nos_x509_subject_name_t             subject_name;
    nos_x509_subject_pubkey_info_t      subject_pubkey;
    /* TODO: Parse extensions. */
} nos_x509_tbs_certificate_t;

typedef struct nos_x509_rsa_pubkey_signature {
    uint8_t                             *signature;
    uint32_t                            signature_len;
} nos_x509_rsa_pubkey_signature_t;

typedef struct nos_x509_certificate_signature {
    nos_x509_rsa_pubkey_signature_t     *rsa_signature;
} nos_x509_certificate_signature_t;

typedef struct nos_x509_certificate {
    nos_x509_tbs_certificate_t          certificate;
    nos_x509_tbs_sig_alg_id_t           signature_algid;
    nos_x509_certificate_signature_t    signature;
} nos_x509_certificate_t;

struct nos_x509_header {
    nos_x509_certificate_t              cert;
    char                                *cert_name;
};

#endif

