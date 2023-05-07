#include <firewall_common.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <doip.h>

fw_event_details_t doip_deserialize(fw_packet_t *pkt)
{
    nos_doip_header_t *doip_h = &pkt->doip_h;
    uint32_t ver = 0;

    fw_pkt_copy_byte(pkt, &doip_h->version);
    fw_pkt_copy_byte(pkt, &doip_h->inv_version);

    ver = ~(doip_h->inv_version);

    /* Versions must match. */
    if (doip_h->version != ver) {
        return FW_EVENT_DESCR_DOIP_VERSION_MISMATCH;
    }

    fw_pkt_copy_2_bytes(pkt, &doip_h->type);
    fw_pkt_copy_4_bytes(pkt, &doip_h->len);

    doip_h->veh_id_resp = NULL;
    doip_h->route_activ_req = NULL;
    doip_h->route_activ_resp = NULL;
    doip_h->status_resp = NULL;
    doip_h->nack = NULL;
    doip_h->alive_chk_resp = NULL;
    doip_h->power_mode_resp = NULL;

    if (doip_h->type == NOS_DOIP_GEN_DOIP_NACK) {
        doip_h->nack = calloc(1, sizeof(nos_doip_header_nack_t));
        if (!doip_h->nack) {
            return FW_EVENT_DESCR_DENY;
        }
        fw_pkt_copy_byte(pkt, &doip_h->nack->value);
    } else if (doip_h->type == NOS_DOIP_RESP_VEH_ID_RESP) {
        doip_h->veh_id_resp = calloc(1, sizeof(nos_doip_veh_id_resp_t));
        if (!doip_h->veh_id_resp) {
            return FW_EVENT_DESCR_DENY;
        }
        fw_pkt_copy_n_bytes(pkt, doip_h->veh_id_resp->vin,
                            sizeof(doip_h->veh_id_resp->vin));
        fw_pkt_copy_2_bytes(pkt, &doip_h->veh_id_resp->logical_address);
        fw_pkt_copy_n_bytes(pkt, doip_h->veh_id_resp->eid,
                            sizeof(doip_h->veh_id_resp->eid));
        fw_pkt_copy_n_bytes(pkt, doip_h->veh_id_resp->gid,
                            sizeof(doip_h->veh_id_resp->gid));
        fw_pkt_copy_byte(pkt, &doip_h->veh_id_resp->further_action);
    } else if (doip_h->type == NOS_DOIP_ROUTING_ACTIVATION_REQ) {
        doip_h->route_activ_req = calloc(1, sizeof(nos_doip_routing_activation_req_t));
        if (!doip_h->route_activ_req) {
            return FW_EVENT_DESCR_DENY;
        }
        fw_pkt_copy_2_bytes(pkt, &doip_h->route_activ_req->source_addr);
        fw_pkt_copy_byte(pkt, &doip_h->route_activ_req->activation_type);
        fw_pkt_copy_4_bytes(pkt, &doip_h->route_activ_req->reserved_by_iso);
        fw_pkt_copy_4_bytes(pkt, &doip_h->route_activ_req->reserved_by_oem);
    } else if (doip_h->type == Nos_DOIP_ROUTING_ACTIVATION_RESP) {
        doip_h->route_activ_resp = calloc(1, sizeof(nos_doip_routing_activation_resp_t));
        if (!doip_h->route_activ_resp) {
            return FW_EVENT_DESCR_DENY;
        }
        fw_pkt_copy_2_bytes(pkt, &doip_h->route_activ_resp->tester_addr);
        fw_pkt_copy_2_bytes(pkt, &doip_h->route_activ_resp->source_addr);
        fw_pkt_copy_byte(pkt, &doip_h->route_activ_resp->resp_code);
        fw_pkt_copy_4_bytes(pkt, &doip_h->route_activ_resp->reserved_by_iso);
    } else if (doip_h->type == NOS_DOIP_ENTITY_STATUS_RESP) {
        doip_h->status_resp = calloc(1, sizeof(nos_doip_entity_status_resp_t));
        if (!doip_h->status_resp) {
            return FW_EVENT_DESCR_DENY;
        }
        fw_pkt_copy_byte(pkt, &doip_h->status_resp->node_type);
        fw_pkt_copy_byte(pkt, &doip_h->status_resp->max_concurrent_sockets);
        fw_pkt_copy_byte(pkt, &doip_h->status_resp->currently_open_sockets);
        fw_pkt_copy_4_bytes(pkt, &doip_h->status_resp->max_data_size);
    } else if (doip_h->type == NOS_DOIP_ALIVE_CHECK_RESP) {
        doip_h->alive_chk_resp = calloc(1, sizeof(nos_doip_alive_check_resp_t));
        if (!doip_h->alive_chk_resp) {
            return FW_EVENT_DESCR_DENY;
        }
        fw_pkt_copy_2_bytes(pkt, &doip_h->alive_chk_resp->source_addr);
    } else if (doip_h->type == NOS_DOIP_DIAG_POWER_MODE_INFO_RESP) {
        doip_h->power_mode_resp = calloc(1, sizeof(nos_diag_power_mode_info_resp_t));
        if (!doip_h->power_mode_resp) {
            return FW_EVENT_DESCR_DENY;
        }
        fw_pkt_copy_byte(pkt, &doip_h->power_mode_resp->power_mode);
    } else if (doip_h->type == NOS_DOIP_DIAG_MESSAGE) {
        doip_h->diag_uds = calloc(1, sizeof(nos_diag_uds_t));
        if (!doip_h->diag_uds) {
            return FW_EVENT_DESCR_DENY;
        }

        fw_pkt_copy_byte(pkt, &doip_h->diag_uds->service_id);
        if (!!(doip_h->diag_uds->service_id & 0x40)) {
            doip_h->diag_uds->is_reply = true;
        } else {
            doip_h->diag_uds->is_reply = false;
        }
        doip_h->diag_uds->service_id ^= 0x40;

        if (doip_h->diag_uds->service_id == 0x10) {
            if (doip_h->diag_uds->is_reply == false) {
                fw_pkt_copy_byte(pkt, &doip_h->diag_uds->sess_control.type);
            } else {
                fw_pkt_copy_byte(pkt, &doip_h->diag_uds->sess_control_ack.type);
                fw_pkt_copy_4_bytes(pkt, &doip_h->diag_uds->sess_control_ack.parameter_record);
            }
        } else if (doip_h->diag_uds->service_id == 0x3F) {
            if (doip_h->diag_uds->is_reply == true) {
                fw_pkt_copy_byte(pkt, &doip_h->diag_uds->error.service_id);
                fw_pkt_copy_byte(pkt, &doip_h->diag_uds->error.code);
            }
        }
    } else if (doip_h->type == NOS_DOIP_DIAG_MESSAGE_ACK) {
        doip_h->diag_uds_ack = calloc(1, sizeof(nos_diag_uds_ack_t));
        if (!doip_h->diag_uds_ack) {
            return FW_EVENT_DESCR_DENY;
        }

        fw_pkt_copy_2_bytes(pkt, &doip_h->diag_uds_ack->source_addr);
        fw_pkt_copy_2_bytes(pkt, &doip_h->diag_uds_ack->target_addr);
        fw_pkt_copy_byte(pkt, &doip_h->diag_uds_ack->ack_code);
    }

    return FW_EVENT_DESCR_ALLOW;
}

void doip_free_header(nos_doip_header_t *doip_h)
{
    if (doip_h) {
        if (doip_h->veh_id_resp)
            free(doip_h->veh_id_resp);
        if (doip_h->route_activ_req)
            free(doip_h->route_activ_req);
        if (doip_h->route_activ_resp)
            free(doip_h->route_activ_resp);
        if (doip_h->nack)
            free(doip_h->nack);
        if (doip_h->alive_chk_resp)
            free(doip_h->alive_chk_resp);
        if (doip_h->power_mode_resp)
            free(doip_h->power_mode_resp);
    }
}
