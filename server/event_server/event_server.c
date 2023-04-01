#include <event_server.h>

#define CMD_ARGS "i:p:"

struct evt_server_command_line_args {
    char ip[20];
    int port;
};

STATIC void usage(const char *progname)
{
    fprintf(stderr, "<%s> <-i ip address>\n"
                    "\t <-p port number>\n", progname);
}

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
        fw_event_fmt_binary_t *bin;
        char pkt[4096];

        ret = recvfrom(fd, pkt, sizeof(pkt), 0, NULL, NULL);
        if (ret < 0) {
            break;
        }

        bin = (fw_event_fmt_binary_t *)pkt;

        printf("receive event : \n");
        printf("\t event_type: %d\n", bin->evt_type);
        printf("\t event_description: %d\n", bin->evt_description);
        printf("\t rule_id: %d\n", bin->rule_id);
    }

bind_err:
    if (fd > 0) {
        close(fd);
    }

    return 0;
}

STATIC int evt_server_parse_command_line_args(int argc, char **argv,
                                struct evt_server_command_line_args *cmd_args)
{
    int ret;

    while ((ret = getopt(argc, argv, CMD_ARGS)) != -1) {
        switch (ret) {
            case 'i':
                strcpy(cmd_args->ip, optarg);
            break;
            case 'p':
                cmd_args->port = atoi(optarg);
            break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct evt_server_command_line_args cmd_args;
    int ret;

    ret = evt_server_parse_command_line_args(argc, argv, &cmd_args);
    if (ret != 0) {
        return -1;
    }

    fw_event_server_init(cmd_args.ip, cmd_args.port);

    return 0;
}

