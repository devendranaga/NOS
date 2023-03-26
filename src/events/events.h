/**
 * @brief - Prototypes for firewall events.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FW_EVENTS_H__
#define __FW_EVENTS_H__

#include <event_def.h>

void *fw_events_init();
void fw_event_add();
void fw_events_deinit(void *);

#endif
