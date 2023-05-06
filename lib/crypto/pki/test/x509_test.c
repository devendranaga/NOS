#include <stdio.h>
#include <x509_parser.h>

int main(int argc, char **argv)
{
    nos_x509_certificate_t cert;
    int ret;

    ret = x509_parse_der(argv[1], &cert);
    if (ret == 0) {
        x509_print(&cert);
    }
}

