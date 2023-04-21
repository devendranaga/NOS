/**
 * @brief - Implement DHCP header parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <firewall_common.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <dhcp.h>

#define DHCP_LEN_DEFAULT 240

fw_event_details_t dhcp_deserialize(fw_packet_t *hdr)
{
    fw_event_details_t ret = FW_EVENT_DESCR_ALLOW;
    dhcp_header_t *dhcp_h = &hdr->dhcp_h;

    memset(&hdr->dhcp_h, 0, sizeof(hdr->dhcp_h));

    fw_pkt_copy_byte(hdr, &dhcp_h->message_type);
    fw_pkt_copy_byte(hdr, &dhcp_h->hardware_type);
    fw_pkt_copy_byte(hdr, &dhcp_h->hardware_address_len);
    fw_pkt_copy_byte(hdr, &dhcp_h->hops);
    fw_pkt_copy_n_bytes(hdr,
                        dhcp_h->transaction_id, sizeof(dhcp_h->transaction_id));
    fw_pkt_copy_2_bytes(hdr, &dhcp_h->seconds_elapsed);

    dhcp_h->bootp_broadcast_flag = !!(hdr->msg[hdr->off] & 0x80);
    hdr->off += 2;

    fw_pkt_copy_4_bytes(hdr, &dhcp_h->client_ipaddr);
    fw_pkt_copy_4_bytes(hdr, &dhcp_h->your_ipaddr);
    fw_pkt_copy_4_bytes(hdr, &dhcp_h->next_server_ipaddr);
    fw_pkt_copy_4_bytes(hdr, &dhcp_h->relay_agent_ipaddr);
    fw_pkt_copy_macaddr(hdr, dhcp_h->client_mac);

    /* Reserved bytes. */
    hdr->off += 10;

    fw_pkt_copy_n_bytes(hdr,
                        dhcp_h->server_hostname, sizeof(dhcp_h->server_hostname));
    fw_pkt_copy_n_bytes(hdr,
                        dhcp_h->boot_filename, sizeof(dhcp_h->boot_filename));
    fw_pkt_copy_n_bytes(hdr, dhcp_h->magic_cookie, sizeof(dhcp_h->magic_cookie));

    /* Parse options. */
    while (hdr->off > hdr->total_len) {
        uint8_t msg_len = 0;
        switch (hdr->msg[hdr->off]) {
            case DHCP_OPT_MESSAGE_TYPE: {
                hdr->off ++;

            } break;
            case DHCP_OPT_CLIENT_ID: {
                hdr->off ++;

                fw_pkt_copy_byte(hdr, &msg_len);
                fw_pkt_copy_byte(hdr, &dhcp_h->options.client_id.hw_type);
                fw_pkt_copy_macaddr(hdr, dhcp_h->options.client_id.client_mac);
            } break;
            case DHCP_OPT_HOST_NAME: {
                hdr->off ++;

                fw_pkt_copy_byte(hdr, &dhcp_h->options.hostname.hostname_len);
                dhcp_h->options.hostname.hostname =
                            calloc(1, dhcp_h->options.hostname.hostname_len);
                if (!dhcp_h->options.hostname.hostname) {
                    return FW_EVENT_DESCR_DENY;
                }

                fw_pkt_copy_n_bytes(hdr,
                                    dhcp_h->options.hostname.hostname,
                                    dhcp_h->options.hostname.hostname_len);
            } break;
            case DHCP_OPT_VENDOR_CLASS_ID: {
                hdr->off ++;

                fw_pkt_copy_byte(hdr, &dhcp_h->options.vendor.len);
                dhcp_h->options.vendor.id = calloc(1, dhcp_h->options.vendor.len);
                if (!dhcp_h->options.vendor.id) {
                    return FW_EVENT_DESCR_DENY;
                }

                fw_pkt_copy_n_bytes(hdr,
                                    dhcp_h->options.vendor.id,
                                    dhcp_h->options.vendor.len);
            } break;
            case DHCP_OPT_PARAMETER_REQ_LIST: {
                hdr->off ++;

                fw_pkt_copy_byte(hdr, &dhcp_h->options.param_list.len);
                dhcp_h->options.param_list.parameter_list =
                            calloc(1, dhcp_h->options.param_list.len);
                if (!dhcp_h->options.param_list.parameter_list) {
                    return FW_EVENT_DESCR_DENY;
                }

                fw_pkt_copy_n_bytes(hdr,
                                    dhcp_h->options.param_list.parameter_list,
                                    dhcp_h->options.param_list.len);
            } break;
            case DHCP_OPT_PARAMETER_END: {
                hdr->off ++;
            } break;
            default: {
                ret = FW_EVENT_DESCR_DHCP_PARAMSET_UNKNOWN;
            }
        }
    }

    return ret;
}

void dhcp_free(fw_packet_t *hdr)
{
    if (hdr->dhcp_h.options.hostname.hostname) {
        free(hdr->dhcp_h.options.hostname.hostname);
    }
    if (hdr->dhcp_h.options.param_list.parameter_list) {
        free(hdr->dhcp_h.options.param_list.parameter_list);
    }
}
