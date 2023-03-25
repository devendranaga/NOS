#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <firewall_common.h>

#define LINUX_RAW_MAC_ADDR 6

struct linux_raw_driver_context {
    char *device_name;
    int fd;
    uint8_t srcmac[LINUX_RAW_MAC_ADDR];
    int dev_index;
};

STATIC int linux_set_promisc(int fd, const char *device_name)
{
    struct ifreq req;
    int ret;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, device_name);
    ret = ioctl(fd, SIOCGIFFLAGS, &req);
    if (ret < 0) {
        return -1;
    }

    req.ifr_flags |= IFF_PROMISC;
    ret = ioctl(fd, SIOCSIFFLAGS, &req);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

STATIC int linux_get_hwaddr(int fd, const char *device_name, uint8_t *mac)
{
    struct ifreq req;
    int ret;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, device_name);
    ret = ioctl(fd, SIOCGIFHWADDR, &req);
    if (ret < 0) {
        return -1;
    }

    mac[0] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[0];
    mac[1] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[1];
    mac[2] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[2];
    mac[3] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[3];
    mac[4] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[4];
    mac[5] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[5];

    return 0;
}

STATIC int linux_bind_to_device(int fd, const char *device_name)
{
    struct ifreq req;
    int ret;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, device_name);
    ret = ioctl(fd, SIOCGIFINDEX, &req);
    if (ret < 0) {
        return -1;
    }

    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &req, sizeof(req));
    if (ret < 0) {
        return -1;
    }

    return req.ifr_ifindex;
}

void *linux_raw_init(const char *device_name)
{
    struct linux_raw_driver_context *context;
    int ret;

    context = calloc(1, sizeof(struct linux_raw_driver_context));
    if (!context) {
        return NULL;
    }

    context->device_name = strdup(device_name);

    /* Create socket interface. */
    context->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (context->fd < 0) {
        return NULL;
    }

    /* set promiscuous mode. */
    ret = linux_set_promisc(context->fd, device_name);
    if (ret < 0) {
        return NULL;
    }

    /* get hwaddr. */
    ret = linux_get_hwaddr(context->fd, device_name, context->srcmac);
    if (ret < 0) {
        return NULL;
    }

    /* bind to device. */
    context->dev_index = linux_bind_to_device(context->fd, device_name);
    if (context->dev_index < 0) {
        return NULL;
    }

    struct sockaddr_ll lladdr;

    /* bind for only one device. */
    memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_ifindex = context->dev_index;
    lladdr.sll_protocol = htons(ETH_P_ALL);
    lladdr.sll_family = AF_PACKET;

    ret = bind(context->fd, (struct sockaddr *)&lladdr, sizeof(lladdr));
    if (ret < 0) {
        return NULL;
    }

    return context;
}

void linux_raw_deinit(void *ctx)
{
    struct linux_raw_driver_context *context = ctx;

    if (context) {
        if (context->device_name) {
            free(context->device_name);
        }
        if (context->fd > 0) {
            close(context->fd);
        }
        free(context);
    }
}

int linux_raw_read(void *ctx, uint8_t *msg, uint32_t msg_len)
{
    struct linux_raw_driver_context *context = ctx;
    socklen_t len = sizeof(struct sockaddr_ll);
    struct sockaddr_ll lladdr;
    int ret;

    memset(&lladdr, 0, sizeof(lladdr));
    ret = recvfrom(context->fd, msg, msg_len, 0, (struct sockaddr *)&lladdr, &len);
    if (ret < 0) {
        return -1;
    }

    return ret;
}


int linux_raw_write(void *ctx, uint8_t *msg, uint32_t msg_len)
{
    const uint8_t mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct linux_raw_driver_context *context = ctx;
    int ret;

    struct sockaddr_ll lladdr;

    memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_ifindex = context->dev_index;
    lladdr.sll_halen = ETH_ALEN;
    memcpy(lladdr.sll_addr, mac, sizeof(mac));

    ret = sendto(context->fd, msg, msg_len, 0,
                 (struct sockaddr *)&lladdr, sizeof(lladdr));
    if (ret < 0) {
        return -1;
    }

    return ret;
}

