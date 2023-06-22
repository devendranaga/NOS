/**
 * @brief - Defines the c based interface for log file uploads.
 * 
 * @copyright - Devendra Naga.
*/
#ifndef __LOG_UPLOAD_C_H__
#define __LOG_UPLOAD_C_H__

#include <cstdint>

namespace nos::logger 
{

enum nos_log_upload_msg_type {
    LOG_UPLOAD_REQUEST,
    LOG_UPLOAD_RESPONSE,
    LOG_UPLOAD_DATA_REQ,
    LOG_UPLOAD_DATA_RESP,
};

struct nos_log_upload_req {
    char filename[64];
    uint8_t filename_len;
    uint32_t filesize;
} __attribute__((__packed__));

enum nos_log_upload_msg_status {
    NO_ERROR,
    DISK_FULL,
    FILE_ALREADY_UPLOADED,
    UPLOAD_COMPLETE,
};

struct nos_log_upload_resp {
    uint8_t handle[8];
    uint32_t seq_no;
    nos_log_upload_msg_status status;
} __attribute__ ((__packed__));

struct nos_log_upload_data_resp {
    uint32_t seq_no;
    nos_log_upload_msg_status status;
} __attribute__ ((__packed__));

struct nos_log_upload_data_req {
    uint8_t handle[8];
    uint8_t end_of_file;
    uint16_t data_len;
    uint8_t data[0];
} __attribute__ ((__packed__));

struct nos_log_upload_msg {
    nos_log_upload_msg_type type;
    uint16_t len;
    uint8_t data[0];
} __attribute__ ((__packed__));

}

#endif
