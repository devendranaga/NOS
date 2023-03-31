/**
 * @brief - Prototypes for firewall events.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#ifndef __FW_EVENTS_H__
#define __FW_EVENTS_H__

#include <stdint.h>
#include <stdlib.h>
#include <os.h>
#include <os_thread.h>
#include <event_def.h>
#include <firewall_common.h>

void *fw_events_init();
void fw_event_add(void *, fw_event_t *evt);
fw_event_t *fw_event_new(fw_event_type_t event,
                         fw_event_details_t event_details);
void fw_event_free(fw_event_t *evt);
void fw_events_deinit(void *);

#endif

