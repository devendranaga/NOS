#include <firewall.h>

#define CMD_ARGS_LIST "i:"

STATIC void usage(const char *progname)
{
    fprintf(stderr, "<%s> -i <interface list separated by comma>",
                    progname);
}

STATIC void get_interface_list(const char *iflist,
                               struct firewall_command_args *cmd_args)
{
    uint32_t len = strlen(iflist);
    uint32_t count = 0;
    uint32_t i = 0;

    /* Read all interfaces. */
    while (i < len) {
        if (iflist[i] == ',') {
            cmd_args->if_list[cmd_args->n_iflist][count] = '\0';
            cmd_args->n_iflist ++;
            count = 0;
        } else {
            cmd_args->if_list[cmd_args->n_iflist][count] = iflist[i];
            count ++;
        }
        i ++;
    }
    /* Last one does not end with ',' and stops with \0. */
    cmd_args->if_list[cmd_args->n_iflist][count] = '\0';
    cmd_args->n_iflist ++;
}

STATIC int parse_command_args(int argc, char **argv,
                              struct firewall_context *fw_ctx)
{
    int ret;

    while ((ret = getopt(argc, argv, CMD_ARGS_LIST)) != -1) {
        switch (ret) {
            case 'i':
                get_interface_list(optarg, &fw_ctx->args);
            break;
            default:
                usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

/* Initialize firewall instance for each interface. */
STATIC int fw_init_all_interfaces(struct firewall_context *fw_ctx)
{
    uint32_t i;

    /* Register network driver callbacks. */
    nw_driver_register(&fw_ctx->nw_drv);

    /* Initialize each interface. */
    for (i = 0; i < fw_ctx->args.n_iflist; i ++) {
        fw_ctx->if_list[i].raw_ctx = fw_ctx->nw_drv.init(
                                fw_ctx->args.if_list[i]);
        if (!fw_ctx->if_list[i].raw_ctx) {
            return -1;
        }
    }

    return 0;
}

/* Deinitialize firewall instance for each interface. */
STATIC void fw_deinit_all_interfaces(struct firewall_context *fw_ctx)
{
    uint32_t i;

    /* deInitialize each interface. */
    for (i = 0; i < fw_ctx->args.n_iflist; i ++) {
        fw_ctx->nw_drv.deinit(fw_ctx->if_list[i].raw_ctx);
    }
}

int main(int argc, char **argv)
{
    struct firewall_context *fw_ctx;
    int ret;

    fw_ctx = calloc(1, sizeof(struct firewall_context));
    if (!fw_ctx) {
        return -1;
    }

    ret = parse_command_args(argc, argv, fw_ctx);
    if (ret < 0) {
        return -1;
    }

    ret = fw_init_all_interfaces(fw_ctx);
    if (ret < 0) {
        goto deinit_fw;
    }

    return 0;

deinit_fw:
    fw_deinit_all_interfaces(fw_ctx);

    return -1;
}

