#include <stdint.h>
#include <string.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <firewall_common.h>

/* Callbacks for Ethertype. */
STATIC const struct ethertype_callback_def {
    uint16_t ethertype;
    fw_event_details_t (*l2_deserialize)(fw_packet_t *hdr);
} ethertype_callbacks[] = {
    {FW_ETHERTYPE_ARP, arp_deserialize},
    {FW_ETHERTYPE_IPV4, ipv4_deserialize},
};

fw_event_details_t parse_protocol(struct fw_packet *pkt)
{
    fw_event_details_t type;
    uint32_t i;

    type = ethernet_deserialize(pkt);
    if (type == FW_EVENT_ALLOW) {
        for (i = 0; i < sizeof(ethertype_callbacks) /
                        sizeof(ethertype_callbacks[0]); i ++) {
            type = ethertype_callbacks[i].l2_deserialize(pkt);
        }
    }

    return type;
}

void fw_copy_macaddr(fw_packet_t *pkt, uint8_t *mac)
{
    memcpy(mac, pkt->msg + pkt->off, FW_MACADDR_LEN);
    pkt->off += FW_MACADDR_LEN;
}

void fw_copy_2_bytes(fw_packet_t *pkt, uint16_t *val)
{
    *val = (pkt->msg[pkt->off] << 8) | (pkt->msg[pkt->off + 1]);
    pkt->off += 2;
}

void fw_copy_byte(fw_packet_t *pkt, uint8_t *val)
{
    *val = pkt->msg[pkt->off];
    pkt->off ++;
}

void fw_copy_4_bytes(fw_packet_t *pkt, uint32_t *val)
{
    *val = (pkt->msg[pkt->off]      << 24) |
           (pkt->msg[pkt->off + 1]  << 16) |
           (pkt->msg[pkt->off + 2] << 8)   |
           (pkt->msg[pkt->off + 3]);
    pkt->off += 4;
}

