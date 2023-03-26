/**
 * @brief - Implements Ethernet parsing.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 * @copyright - 2023-present All rights reserved.
 */
#include <stdio.h>
#include <protocol_generic.h>
#include <fw_pkt.h>
#include <ethernet.h>

fw_event_type_t ethernet_deserialize(fw_packet_t *hdr)
{
    fw_event_type_t type = FW_EVENT_ALLOW;

    fw_copy_macaddr(hdr, hdr->eh.dst);
    fw_copy_macaddr(hdr, hdr->eh.src);
    fw_copy_2_bytes(hdr, &hdr->eh.ethertype);

#if 0
    printf("dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    hdr->eh.dst[0], hdr->eh.dst[1], hdr->eh.dst[2],
                    hdr->eh.dst[3], hdr->eh.dst[4], hdr->eh.dst[5]);
    printf("src: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    hdr->eh.src[0], hdr->eh.src[1], hdr->eh.src[2],
                    hdr->eh.src[3], hdr->eh.src[4], hdr->eh.src[5]);
    printf("ethertype 0x%04x\n", hdr->eh.ethertype);
#endif

    return type;
}


