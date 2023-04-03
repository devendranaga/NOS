/**
 * @brief - Implements PTP Header.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __LIB_PROTOCOLS_PTP_H__
#define __LIB_PROTOCOLS_PTP_H__

#define PTP_SECURITY_BIT            (1 << 15)
#define PTP_PROFILE_SPEC_2_BIT      (1 << 14)
#define PTP_PROFILE_SPEC_1_BIT      (1 << 13)
#define PTP_UNICAST_BIT             (1 << 10)
#define PTP_TWO_STEP_BIT            (1 << 9)
#define PTP_ALTERNATE_MASTER_BIT    (1 << 8)
#define PTP_SYNC_UNCERTAIN_BIT      (1 << 6)
#define PTP_FREQ_TRACEABLE_BIT      (1 << 5)
#define PTP_TIME_TRACEABLE_BIT      (1 << 4)
#define PTP_TIMESCALE_BIT           (1 << 3)
#define PTP_UTC_REASONABLE_BIT      (1 << 2)
#define PTP_LI_59_BIT               (1 << 1)
#define PTP_LI_61_BIT               (1 << 0)

/* Implements PTP Header. */
struct ptp_header {
    uint8_t major_sdoid;
    uint8_t message_type;
    uint8_t minor_ptp_version;
    uint8_t version_ptp;
    uint16_t message_len;
    uint8_t domain_no;
    uint8_t minor_sdoid;
    uint16_t flags;
    uint64_t corrections_ns;
    uint16_t corrections_sub_ns;
    uint32_t message_type_specific;
    uint8_t clk_id[8];
    uint16_t source_port_id;
    uint16_t seq_id;
    uint8_t control_field;
    uint8_t log_message_period;
    uint64_t origin_timestamp_sec;
    uint32_t origin_timestamp_ns;
};

#define PTP_HAS_SECURITY_BIT_SET(__ptp)             (!!(__ptp->flags & PTP_SECURITY_BIT))
#define PTP_HAS_PROFILE_SPEC_2_BIT_SET(__ptp)       (!!(__ptp->flags & PTP_PROFILE_SPEC_2_BIT))
#define PTP_HAS_PROFILE_SPEC_1_BIT_SET(__ptp)       (!!(__ptp->flags & PTP_PROFILE_SPEC_1_BIT))
#define PTP_HAS_UNICAST_BIT_SET(__ptp)              (!!(__ptp->flags & PTP_UNICAST_BIT))
#define PTP_HAS_TWO_STEP_BIT_SET(__ptp)             (!!(__ptp->flags & PTP_TWO_STEP_BIT))
#define PTP_HAS_ALTERNATE_MASTER_BIT_SET(__ptp)     (!!(__ptp->flags & PTP_ALTERNATE_MASTER_BIT))
#define PTP_HAS_SYNC_UNCERTAIN_BIT_SET(__ptp)       (!!(__ptp->flags & PTP_SYNC_UNCERTAIN_BIT))
#define PTP_HAS_FREQ_TRACEABLE_BIT_SET(__ptp)       (!!(__ptp->flags & PTP_FREQ_TRACEABLE_BIT))
#define PTP_HAS_TIME_TRACEABLE_BIT_SET(__ptp)       (!!(__ptp->flags & PTP_TIME_TRACEABLE_BIT))
#define PTP_HAS_TIMESCALE_BIT_SET(__ptp)            (!!(__ptp->flags & PTP_TIMESCALE_BIT))
#define PTP_HAS_UTC_REASONABLE_BIT_SET(__ptp)       (!!(__ptp->flags & PTP_UTC_REASONABLE_BIT))
#define PTP_LI_59_BIT_SET(__ptp)                    (!!(__ptp->flags & PTP_LI_59_BIT))
#define PTP_LI_61_BIT_SET(__ptp)                    (!!(__ptp->flags & PTP_LI_61_BIT))

typedef struct ptp_header ptp_header_t;

#endif

