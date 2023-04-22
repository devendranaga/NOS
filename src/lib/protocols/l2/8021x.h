#ifndef __LIB_PROTOCOLS_8021X_H__
#define __LIB_PROTOCOLS_8021X_H__

#include <stdint.h>
#include <stdbool.h>

#define EAPOL_MKA                           5

#define MKA_VERSION_1                       1
#define MKA_VERSION_3                       3

#define MKA_KEYSERVER_PRIORITY_0            0
#define MKA_KEYSERVER_PRIORITY_255          255

#define MACSEC_CAP_NONE                     0
#define MACSEC_CAP_INTEG_CONF_WITH_OFFSET   3

#define MKA_SCI_LEN                         8
#define MKA_MI_LEN                          12

#define MKA_ALGORITHM_AGILITY               0x0080C201

#define MKA_CKN_LEN                         32

#define MKA_MAX_PEERS                       16

#define MKA_AES_KEYWRAP_LEN_MAX             40

#define MKA_ICV_LEN_MAX                     16

#define MKA_BPS_LEN                         32

#define MKA_LIVE_PEERLIST_PARAMSET          1
#define MKA_POTENTIAL_PEERLIST_PARAMSET     2
#define MKA_MACSEC_SAKUSE_PARAMSET          3
#define MKA_DIST_SAK_PARAMSET               4
#define MKA_ICV_PARAMSET                    255

/**
 * MKA Basic Parameter Set.
 */
struct ieee8021x_eapol_mka_basic_paramset {
    uint8_t         version;
    uint8_t         key_server_priority;
    bool            key_server;
    bool            macsec_desired;
    uint8_t         macsec_capability;
    uint16_t        paramset_len;
    uint8_t         sci[MKA_SCI_LEN];
    uint8_t         actor_mi[MKA_MI_LEN];
    uint32_t        actor_mn;
    uint32_t        alg_agility;
    uint8_t         ckn[MKA_CKN_LEN];
    uint8_t         ckn_len;
};

/**
 * MKA Peer Information.
 */
struct ieee8021x_eapol_mka_peer {
    uint8_t         mi[MKA_MI_LEN];
    uint32_t        mn;
};

/**
 * MKA Potential Peer Lists.
 */
struct ieee8021x_eapol_mka_potential_paramset {
    uint16_t                            paramset_len;
    uint8_t                             num_peers;
    struct ieee8021x_eapol_mka_peer     peer_list[MKA_MAX_PEERS];
};

/**
 * MKA Live Peer Lists.
 */
struct ieee8021x_eapol_mka_live_paramset {
    uint16_t                            paramset_len;
    uint8_t                             num_peers;
    struct ieee8021x_eapol_mka_peer     peer_list[MKA_MAX_PEERS];
};

/**
 * MKA Distributed SAK Parameter Set.
 */
struct ieee8021x_eapol_mka_dist_sak_paramset {
    uint8_t         dist_an;
    uint8_t         conf_offset;
    uint16_t        paramset_len;
    uint8_t         cipher[8];
    uint32_t        key_number;
    uint8_t         key_wrap_len;
    uint8_t         key_wrap[MKA_AES_KEYWRAP_LEN_MAX];
};

struct ieee8021x_eapol_mka_macsec_sak_paramset {
    uint8_t         lan;
    bool            ltx;
    bool            lrx;
    uint8_t         oan;
    bool            otx;
    bool            orx;
    bool            ptx;
    bool            prx;
    bool            dp;
    uint16_t        paramset_len;
    uint8_t         latest_mi[MKA_MI_LEN];
    uint32_t        latest_kn;
    uint32_t        latest_lowest_pn;
    uint8_t         old_mi[MKA_MI_LEN];
    uint32_t        old_kn;
    uint32_t        old_lowest_pn;
};

struct ieee8021x_eapol_mka_icv_paramset {
    uint16_t        paramset_len;
    uint8_t         icv[MKA_ICV_LEN_MAX];
};

enum mka_paramset_type {
    MKA_BASIC_PARAMSET_BIT          = 0x0001,
    MKA_POTENTIAL_PARAMSET_BIT      = 0x0002,
    MKA_LIVE_PARAMSET_BIT           = 0x0004,
    MKA_DIST_SAK_PARAMSET_BIT       = 0x0008,
    MKA_MACSEC_SAK_USE_PARAMSET_BIT = 0x0010,
    MKA_ICV_PARAMSET_BIT            = 0x0020,
};

typedef enum mka_paramset_type mka_paramset_type_t;

struct ieee8021x_eapol_mka {
    mka_paramset_type_t paramset_preset;
    struct ieee8021x_eapol_mka_basic_paramset bp;
    struct ieee8021x_eapol_mka_potential_paramset pp;
    struct ieee8021x_eapol_mka_live_paramset lp;
    struct ieee8021x_eapol_mka_dist_sak_paramset dp;
    struct ieee8021x_eapol_mka_macsec_sak_paramset mp;
    struct ieee8021x_eapol_mka_icv_paramset ip;
};

struct ieee8021x_eapol {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    struct ieee8021x_eapol_mka mka;
};

struct ieee8021x_header {
    struct ieee8021x_eapol eapol;
};

typedef struct ieee8021x_header ieee8021x_header_t;

#endif

