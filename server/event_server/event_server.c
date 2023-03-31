#include <event_server.h>

int fw_event_server_init(const char *ipaddr, int port)
{
    struct sockaddr_in serv;
    int ret;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    serv.sin_addr.s_addr = inet_addr(ipaddr);
    serv.sin_port = htons(port);
    serv.sin_family = AF_INET;

    ret = bind(fd, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        goto bind_err;
    }

    while (1) {
        char pkt[4096];

        ret = recvfrom(fd, pkt, sizeof(pkt), 0, NULL, NULL);
        if (ret < 0) {
            break;
        }
        printf("received %d bytes\n", ret);
    }

bind_err:
    if (fd > 0) {
        close(fd);
    }

    return 0;
}

int main(int argc, char **argv)
{
    fw_event_server_init("127.0.0.1", 2022);
    return 0;
}

