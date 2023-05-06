#include <x509.h>

int x509_parse_der(const char *filename, nos_x509_certificate_t *cert);
int x509_print(nos_x509_certificate_t *cert);
